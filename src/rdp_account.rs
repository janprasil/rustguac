//! Windows account handling for the RDP launcher.
//!
//! The account name comes from the verified email: the login part in the primary
//! domain, login and domain for external users. A missing account is created
//! and managed here. An existing account is used only after its
//! owner proves the password, which is then stored for the next launch.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Mod, Scope, SearchEntry};
use rand::{seq::SliceRandom, RngExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::rdp_identity::{required, Identity};
use crate::vault::VaultClient;

const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Signs in with a typed password only. Never looked up, changed or stored.
const MANUAL_ONLY: &str = "administrator";
/// Never usable through the launcher.
const BLOCKED: [&str; 2] = ["guest", "krbtgt"];

const RID_ADMINISTRATOR: u32 = 500;
const RID_GUEST: u32 = 501;
const RID_KRBTGT: u32 = 502;

const UAC_DISABLED: u32 = 0x2;
const UAC_NORMAL: u32 = 0x200;
const EXPIRED: &str = "Your Windows password has expired. Choose a new one on the desktop list.";

pub(crate) enum Failure {
    /// The user has to type the Windows password.
    NeedPassword(&'static str),
    /// The password expired and the owner has to choose a new one.
    NeedNewPassword(&'static str),
    Refused(StatusCode, &'static str),
}

pub(crate) type Credentials = (String, String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    /// Account created by the launcher.
    Managed,
    /// Password typed by the owner of an existing account.
    Stored,
    /// Existing account whose password the launcher took over.
    Taken,
}

#[derive(Clone, Serialize, Deserialize)]
struct Record {
    username: String,
    password: String,
    mode: Mode,
    /// New password written before AD is asked to switch to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<String>,
    /// AD rejected the password, so it must not be tried again.
    #[serde(default)]
    stale: bool,
    /// AD marks the account as privileged, so no takeover.
    #[serde(default)]
    privileged: bool,
}

impl Record {
    fn new(username: &str, password: &str, mode: Mode) -> Self {
        Self {
            username: username.to_owned(),
            password: password.to_owned(),
            mode,
            pending: None,
            stale: false,
            privileged: false,
        }
    }

    /// Administrators keep their own password.
    fn allows_takeover(&self, identity: &Identity, name: &str) -> bool {
        !identity.admin
            && !self.privileged
            && !self.stale
            && self.mode == Mode::Stored
            && self.username == name
    }
}

struct Account {
    dn: String,
    description: Option<String>,
    flags: Option<u32>,
    rid: Option<u32>,
    /// `adminCount` set by AD on members of protected groups.
    privileged: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Kind {
    Managed { pending: bool },
    OtherOwner,
    Existing,
    ManualOnly,
    Blocked,
}

enum BindOutcome {
    Valid,
    Expired,
    Rejected,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AccountName {
    /// sAMAccountName, at most 20 characters.
    pub login: String,
    /// Untruncated form, used for the UPN of new accounts.
    pub full: String,
}

/// Maps verified emails to Windows account names.
pub(crate) struct Naming {
    primary_domain: String,
    allow_external: bool,
}

impl Naming {
    pub fn new(primary_domain: &str, allow_external: bool) -> Self {
        Self {
            primary_domain: primary_domain.trim().to_ascii_lowercase(),
            allow_external,
        }
    }

    /// `None` when the email may not have a Windows account.
    pub fn account(&self, identity: &Identity) -> Option<AccountName> {
        let email = identity.email.to_ascii_lowercase();
        let (login, domain) = email.split_once('@')?;
        let safe = |part: &str| {
            part.bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'.' | b'_' | b'-'))
        };
        if !safe(login) || !safe(domain) || login.trim_matches('.').is_empty() {
            return None;
        }
        if domain == self.primary_domain {
            let name: String = login.chars().take(20).collect();
            let name = name.trim_end_matches('.').to_owned();
            return Some(AccountName {
                full: name.clone(),
                login: name,
            });
        }
        if !self.allow_external {
            return None;
        }
        let full = format!("{login}_{}", domain.replace('.', "_"));
        let login = if full.len() <= 20 {
            full.clone()
        } else {
            // The hash keeps truncated names of different emails apart.
            let hash = hex::encode(Sha256::digest(email.as_bytes()));
            format!("{}-{}", &full[..13], &hash[..6])
        };
        Some(AccountName { login, full })
    }
}

pub(crate) fn is_manual_only(username: &str) -> bool {
    username.eq_ignore_ascii_case(MANUAL_ONLY)
}

fn classify(account: &Account, owner: &str, users_ou: &str, bind_dn: &str) -> Kind {
    if account.dn.eq_ignore_ascii_case(bind_dn)
        || matches!(account.rid, Some(RID_GUEST | RID_KRBTGT))
    {
        return Kind::Blocked;
    }
    // The built-in administrator stays protected even when renamed.
    if account.rid == Some(RID_ADMINISTRATOR) {
        return Kind::ManualOnly;
    }
    let suffix = format!(",{}", users_ou.to_ascii_lowercase());
    if !account.dn.to_ascii_lowercase().ends_with(&suffix) {
        return Kind::Existing;
    }
    match account.description.as_deref() {
        Some(marker) if marker == owner => Kind::Managed { pending: false },
        Some(marker) if marker == format!("{owner}:pending") => Kind::Managed { pending: true },
        _ => Kind::OtherOwner,
    }
}

fn domain_base(users_ou: &str) -> Option<String> {
    let parts: Vec<&str> = users_ou
        .split(',')
        .map(str::trim)
        .filter(|part| part.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("DC=")))
        .collect();
    (!parts.is_empty()).then(|| parts.join(","))
}

fn rid(sid: &[u8]) -> Option<u32> {
    let tail: [u8; 4] = sid.get(sid.len().checked_sub(4)?..)?.try_into().ok()?;
    Some(u32::from_le_bytes(tail))
}

fn attribute<'a>(entry: &'a SearchEntry, name: &str) -> Option<&'a str> {
    let (_, values) = entry
        .attrs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))?;
    match values.as_slice() {
        [value] => Some(value.as_str()),
        _ => None,
    }
}

fn binary_attribute<'a>(entry: &'a SearchEntry, name: &str) -> Option<&'a [u8]> {
    entry
        .bin_attrs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, values)| values.first())
        .map(Vec::as_slice)
        // A value that happens to be valid UTF-8 lands in the text map.
        .or_else(|| attribute(entry, name).map(str::as_bytes))
}

fn encode_password(password: &str) -> Vec<u8> {
    format!("\"{password}\"")
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect()
}

pub(crate) fn generate_password() -> String {
    let classes: [&[u8]; 4] = [
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        b"abcdefghijklmnopqrstuvwxyz",
        b"0123456789",
        b"!@#%+=_-",
    ];
    let all = classes.concat();
    let mut rng = rand::rng();
    let mut password: Vec<u8> = classes
        .iter()
        .map(|set| set[rng.random_range(0..set.len())])
        .collect();
    password.extend((password.len()..24).map(|_| all[rng.random_range(0..all.len())]));
    password.shuffle(&mut rng);
    password.into_iter().map(char::from).collect()
}

fn failed(step: &'static str, message: &'static str) -> Failure {
    tracing::warn!(%step, "RDP account handling failed");
    Failure::Refused(StatusCode::BAD_GATEWAY, message)
}

fn ad_failed(step: &'static str) -> Failure {
    failed(step, "Could not prepare your Windows account.")
}

fn store_failed(step: &'static str) -> Failure {
    failed(step, "The credential store is temporarily unavailable.")
}

async fn read_record(vault: &VaultClient, key: &str) -> Result<Option<Record>, Failure> {
    match vault.read_rdp_record(key).await {
        Ok(Some(value)) => serde_json::from_value(value)
            .map(Some)
            .map_err(|_| store_failed("credential record")),
        Ok(None) => Ok(None),
        Err(_) => Err(store_failed("credential read")),
    }
}

async fn write_record(vault: &VaultClient, key: &str, record: &Record) -> Result<(), Failure> {
    let value = serde_json::to_value(record).map_err(|_| store_failed("credential record"))?;
    vault
        .put_rdp_record(key, &value)
        .await
        .map_err(|_| store_failed("credential write"))
}

pub(crate) struct Directory {
    url: Url,
    tls: Arc<rustls::ClientConfig>,
    bind_dn: String,
    bind_password: String,
    users_ou: String,
    base_dn: String,
    rdp_group: String,
    admin_group: Option<String>,
    pub domain: String,
    pub naming: Naming,
}

impl Directory {
    pub fn from_env() -> Result<Self, String> {
        let url = Url::parse(&required("AD_LDAPS_URL")?).map_err(|_| "AD_LDAPS_URL is invalid")?;
        if url.scheme() != "ldaps"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
        {
            return Err("AD_LDAPS_URL must be an LDAPS server URL".into());
        }
        let ca = std::fs::read(required("AD_CA_CERT_PATH")?)
            .map_err(|_| "Could not read AD_CA_CERT_PATH")?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca.as_slice()) {
            roots
                .add(cert.map_err(|_| "Invalid AD CA certificate")?)
                .map_err(|_| "Invalid AD CA certificate")?;
        }
        if roots.is_empty() {
            return Err("AD_CA_CERT_PATH contains no CA certificates".into());
        }
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let users_ou = required("AD_USERS_OU")?;
        let base_dn = domain_base(&users_ou).ok_or("AD_USERS_OU must include DC= components")?;
        Ok(Self {
            url,
            tls: Arc::new(tls),
            bind_dn: required("AD_BIND_DN")?,
            bind_password: required("AD_BIND_PASSWORD")?,
            users_ou,
            base_dn,
            rdp_group: required("AD_RDP_GROUP_DN")?,
            admin_group: required("AD_RDP_ADMIN_GROUP_DN").ok(),
            domain: required("AD_DOMAIN")?,
            naming: Naming::new(
                &required("RDP_PRIMARY_EMAIL_DOMAIN")?,
                match std::env::var("RDP_ALLOW_EXTERNAL").as_deref() {
                    Ok("true") => true,
                    Ok("false" | "") | Err(std::env::VarError::NotPresent) => false,
                    _ => return Err("RDP_ALLOW_EXTERNAL must be true or false".into()),
                },
            ),
        })
    }

    /// Whether the owner can ask the launcher to take over the password.
    pub async fn takeover_available(
        &self,
        identity: &Identity,
        vault: &VaultClient,
    ) -> Result<bool, Failure> {
        let Some(name) = self
            .naming
            .account(identity)
            .filter(|name| !is_manual_only(&name.login))
        else {
            return Ok(false);
        };
        Ok(read_record(vault, &identity.fingerprint)
            .await?
            .is_some_and(|record| record.allows_takeover(identity, &name.login)))
    }

    pub fn has_admin_group(&self) -> bool {
        self.admin_group.is_some()
    }

    /// Credentials for one RDP launch. `live` means another desktop of this
    /// user may still be authenticating, so the password must stay unchanged.
    pub async fn credentials(
        &self,
        identity: &Identity,
        vault: Option<&VaultClient>,
        typed: Option<String>,
        new_password: Option<String>,
        live: bool,
    ) -> Result<Credentials, Failure> {
        let account_name = self.naming.account(identity).ok_or(Failure::Refused(
            StatusCode::FORBIDDEN,
            "Your email cannot be used as a Windows login.",
        ))?;
        let name = account_name.login.clone();
        let blocked = Failure::Refused(
            StatusCode::FORBIDDEN,
            "This account cannot be used through this page.",
        );
        // Decided before any directory or store access.
        if is_manual_only(&name) {
            if new_password.is_some() {
                return Err(Failure::Refused(
                    StatusCode::FORBIDDEN,
                    "The password of this account cannot be changed here.",
                ));
            }
            return typed
                .map(|password| (name, password))
                .ok_or(Failure::NeedPassword("Enter your Windows password."));
        }
        if BLOCKED.contains(&name.as_str()) {
            return Err(blocked);
        }
        let vault = vault.ok_or_else(|| store_failed("credential store unavailable"))?;
        let mut ldap = self.service().await?;
        let account = self.find(&mut ldap, &name).await?;
        let kind = account
            .as_ref()
            .map(|a| classify(a, &identity.owner, &self.users_ou, &self.bind_dn));
        let result = match (account, kind) {
            (None, _) => self.create(&mut ldap, identity, vault, &account_name).await,
            (Some(_), Some(Kind::Blocked)) => Err(blocked),
            (Some(_), Some(Kind::ManualOnly)) => typed
                .map(|password| (name.clone(), password))
                .ok_or(Failure::NeedPassword("Enter your Windows password.")),
            (Some(_), Some(Kind::OtherOwner)) => Err(Failure::Refused(
                StatusCode::FORBIDDEN,
                "This Windows login belongs to a different user.",
            )),
            (Some(account), Some(Kind::Managed { pending })) => {
                self.managed(&mut ldap, identity, vault, &name, &account, pending, live)
                    .await
            }
            (Some(account), _) => match (typed, new_password) {
                (Some(old), Some(new)) => {
                    self.change_expired(&mut ldap, identity, vault, &name, &account, old, new)
                        .await
                }
                (typed, _) => {
                    self.existing(&mut ldap, identity, vault, &name, &account, typed)
                        .await
                }
            },
        };
        let _ = ldap.with_timeout(IO_TIMEOUT).unbind().await;
        result
    }

    /// Replace the stored password of an existing account with a generated one.
    /// This is a password change, so it needs the current password and no
    /// extra directory rights.
    pub async fn take_over(&self, identity: &Identity, vault: &VaultClient) -> Result<(), Failure> {
        let unavailable = Failure::Refused(
            StatusCode::CONFLICT,
            "Sign in with your Windows password first.",
        );
        let name = self
            .naming
            .account(identity)
            .map(|name| name.login)
            .filter(|name| !is_manual_only(name) && !BLOCKED.contains(&name.as_str()))
            .ok_or(Failure::Refused(
                StatusCode::FORBIDDEN,
                "The password of this account cannot be managed here.",
            ))?;
        let Some(record) = read_record(vault, &identity.fingerprint)
            .await?
            .filter(|r| r.allows_takeover(identity, &name))
        else {
            return Err(unavailable);
        };
        let mut ldap = self.service().await?;
        let account = self.find(&mut ldap, &name).await?.ok_or(unavailable)?;
        if account.privileged
            || classify(&account, &identity.owner, &self.users_ou, &self.bind_dn) != Kind::Existing
        {
            return Err(Failure::Refused(
                StatusCode::FORBIDDEN,
                "The password of this account cannot be managed here.",
            ));
        }
        if !matches!(
            self.bind_as(&account.dn, &record.password).await?,
            BindOutcome::Valid
        ) {
            let stale = Record {
                stale: true,
                ..record
            };
            write_record(vault, &identity.fingerprint, &stale).await?;
            return Err(Failure::NeedPassword(
                "Your stored password no longer works.",
            ));
        }
        self.change_stored(&mut ldap, identity, vault, &account.dn, record)
            .await?;
        let _ = ldap.with_timeout(IO_TIMEOUT).unbind().await;
        Ok(())
    }

    async fn change_stored(
        &self,
        ldap: &mut Ldap,
        identity: &Identity,
        vault: &VaultClient,
        dn: &str,
        record: Record,
    ) -> Result<Record, Failure> {
        let next = generate_password();
        // Keep both passwords until AD confirms, so neither can get lost.
        let pending = Record {
            pending: Some(next.clone()),
            ..record.clone()
        };
        write_record(vault, &identity.fingerprint, &pending).await?;
        let changed = self
            .change_password(ldap, dn, &record.password, &next)
            .await;
        if changed.is_err() {
            write_record(vault, &identity.fingerprint, &record).await?;
            return Err(failed(
                "AD password change",
                "AD refused the password change. The minimum password age may not have passed.",
            ));
        }
        let taken = Record::new(&record.username, &next, Mode::Taken);
        write_record(vault, &identity.fingerprint, &taken).await?;
        Ok(taken)
    }

    async fn existing(
        &self,
        ldap: &mut Ldap,
        identity: &Identity,
        vault: &VaultClient,
        name: &str,
        account: &Account,
        typed: Option<String>,
    ) -> Result<Credentials, Failure> {
        let dn = account.dn.as_str();
        let key = &identity.fingerprint;
        let password = if let Some(password) = typed {
            // An empty password would be an anonymous bind, which succeeds.
            match self.bind_as(dn, &password).await? {
                BindOutcome::Valid => {}
                BindOutcome::Expired => return Err(Failure::NeedNewPassword(EXPIRED)),
                BindOutcome::Rejected => {
                    return Err(Failure::NeedPassword(
                        "Windows did not accept this password.",
                    ))
                }
            }
            let record = Record {
                privileged: account.privileged,
                ..Record::new(name, &password, Mode::Stored)
            };
            write_record(vault, key, &record).await?;
            password
        } else {
            let Some(record) = read_record(vault, key)
                .await?
                .filter(|r| r.username == name && !r.stale && r.mode != Mode::Managed)
            else {
                return Err(Failure::NeedPassword("Enter your Windows password."));
            };
            self.verify_stored(ldap, identity, vault, dn, record)
                .await?
        };
        self.sync_groups(ldap, dn, identity.admin).await?;
        Ok((name.to_owned(), password))
    }

    async fn verify_stored(
        &self,
        ldap: &mut Ldap,
        identity: &Identity,
        vault: &VaultClient,
        dn: &str,
        mut record: Record,
    ) -> Result<String, Failure> {
        let key = &identity.fingerprint;
        // An interrupted change may have left the new password active.
        if let Some(next) = record.pending.take() {
            if matches!(self.bind_as(dn, &next).await?, BindOutcome::Valid) {
                let taken = Record::new(&record.username, &next, Mode::Taken);
                write_record(vault, key, &taken).await?;
                return Ok(next);
            }
        }
        match self.bind_as(dn, &record.password).await? {
            BindOutcome::Valid => Ok(record.password),
            BindOutcome::Expired if record.mode == Mode::Taken => Ok(self
                .change_stored(ldap, identity, vault, dn, record)
                .await?
                .password),
            BindOutcome::Expired => Err(Failure::NeedNewPassword(EXPIRED)),
            BindOutcome::Rejected => {
                record.stale = true;
                write_record(vault, key, &record).await?;
                Err(Failure::NeedPassword(
                    "Your stored password no longer works.",
                ))
            }
        }
    }

    /// The owner replaces an expired password of their own account.
    #[allow(clippy::too_many_arguments)]
    async fn change_expired(
        &self,
        ldap: &mut Ldap,
        identity: &Identity,
        vault: &VaultClient,
        name: &str,
        account: &Account,
        old: String,
        new: String,
    ) -> Result<Credentials, Failure> {
        if !matches!(self.bind_as(&account.dn, &old).await?, BindOutcome::Expired) {
            return Err(Failure::NeedPassword(
                "The password can be changed here only after it expires.",
            ));
        }
        self.change_password(ldap, &account.dn, &old, &new)
            .await
            .map_err(|_| {
                Failure::NeedNewPassword(
                    "Windows refused the new password. Check the password policy.",
                )
            })?;
        self.existing(ldap, identity, vault, name, account, Some(new))
            .await
    }

    /// A password change (not a reset): AD checks the old password itself.
    async fn change_password(
        &self,
        ldap: &mut Ldap,
        dn: &str,
        old: &str,
        new: &str,
    ) -> Result<(), ldap3::LdapError> {
        let attr = b"unicodePwd".to_vec();
        ldap.with_timeout(IO_TIMEOUT)
            .modify(
                dn,
                vec![
                    Mod::Delete(attr.clone(), HashSet::from([encode_password(old)])),
                    Mod::Add(attr, HashSet::from([encode_password(new)])),
                ],
            )
            .await
            .and_then(ldap3::LdapResult::success)
            .map(|_| ())
    }

    async fn create(
        &self,
        ldap: &mut Ldap,
        identity: &Identity,
        vault: &VaultClient,
        account_name: &AccountName,
    ) -> Result<Credentials, Failure> {
        let name = account_name.login.as_str();
        let dn = format!("CN={name},{}", self.users_ou);
        let upn = format!("{}@{}", account_name.full, self.domain);
        let pending = format!("{}:pending", identity.owner);
        // No `mail`: directory sync could match it to the cloud user and
        // overwrite that user's cloud password.
        ldap.with_timeout(IO_TIMEOUT)
            .add(
                &dn,
                vec![
                    ("objectClass", HashSet::from(["user"])),
                    ("cn", HashSet::from([name])),
                    ("sAMAccountName", HashSet::from([name])),
                    ("userPrincipalName", HashSet::from([upn.as_str()])),
                    ("displayName", HashSet::from([identity.email.as_str()])),
                    ("userAccountControl", HashSet::from(["514"])),
                    ("description", HashSet::from([pending.as_str()])),
                ],
            )
            .await
            .and_then(ldap3::LdapResult::success)
            .map_err(|_| ad_failed("AD user creation"))?;
        self.reset(ldap, identity, vault, name, &dn, true).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn managed(
        &self,
        ldap: &mut Ldap,
        identity: &Identity,
        vault: &VaultClient,
        name: &str,
        account: &Account,
        pending: bool,
        live: bool,
    ) -> Result<Credentials, Failure> {
        let flags = account.flags.ok_or_else(|| ad_failed("AD account flags"))?;
        let usable = if pending {
            flags == (UAC_NORMAL | UAC_DISABLED)
        } else {
            flags & (UAC_NORMAL | UAC_DISABLED) == UAC_NORMAL
        };
        if !usable {
            return Err(ad_failed("AD account disabled or unsuitable"));
        }
        if live && !pending {
            let record = read_record(vault, &identity.fingerprint)
                .await?
                .filter(|r| r.username == name)
                .ok_or_else(|| store_failed("credential missing for a live session"))?;
            self.sync_groups(ldap, &account.dn, identity.admin).await?;
            return Ok((name.to_owned(), record.password));
        }
        self.reset(ldap, identity, vault, name, &account.dn, pending)
            .await
    }

    /// Set a fresh password on an account the launcher created.
    async fn reset(
        &self,
        ldap: &mut Ldap,
        identity: &Identity,
        vault: &VaultClient,
        name: &str,
        dn: &str,
        enable: bool,
    ) -> Result<Credentials, Failure> {
        self.sync_groups(ldap, dn, identity.admin).await?;
        let password = generate_password();
        ldap.with_timeout(IO_TIMEOUT)
            .modify(
                dn,
                vec![Mod::Replace(
                    b"unicodePwd".to_vec(),
                    HashSet::from([encode_password(&password)]),
                )],
            )
            .await
            .and_then(ldap3::LdapResult::success)
            .map_err(|_| ad_failed("AD password rotation"))?;
        if enable {
            ldap.with_timeout(IO_TIMEOUT)
                .modify(
                    dn,
                    vec![
                        Mod::Replace("userAccountControl", HashSet::from(["512"])),
                        Mod::Replace("description", HashSet::from([identity.owner.as_str()])),
                    ],
                )
                .await
                .and_then(ldap3::LdapResult::success)
                .map_err(|_| ad_failed("AD account activation"))?;
        }
        let record = Record::new(name, &password, Mode::Managed);
        write_record(vault, &identity.fingerprint, &record).await?;
        Ok((name.to_owned(), password))
    }

    async fn sync_groups(&self, ldap: &mut Ldap, dn: &str, admin: bool) -> Result<(), Failure> {
        let add = || vec![Mod::Add("member", HashSet::from([dn]))];
        // 20 and 68: already a member.
        let result = ldap
            .with_timeout(IO_TIMEOUT)
            .modify(&self.rdp_group, add())
            .await
            .map_err(|_| ad_failed("AD RDP group membership"))?;
        if !matches!(result.rc, 0 | 20 | 68) {
            return Err(ad_failed("AD RDP group membership"));
        }
        let Some(group) = &self.admin_group else {
            return Ok(());
        };
        let (modification, accepted): (_, &[u32]) = if admin {
            (add(), &[0, 20, 68])
        } else {
            // 16 and 53: was not a member.
            (
                vec![Mod::Delete("member", HashSet::from([dn]))],
                &[0, 16, 53],
            )
        };
        let result = ldap
            .with_timeout(IO_TIMEOUT)
            .modify(group, modification)
            .await
            .map_err(|_| ad_failed("AD admin group membership"))?;
        if !accepted.contains(&result.rc) {
            return Err(ad_failed("AD admin group membership"));
        }
        Ok(())
    }

    async fn connect(&self) -> Result<Ldap, Failure> {
        let settings = LdapConnSettings::new()
            .set_conn_timeout(IO_TIMEOUT)
            .set_config(self.tls.clone());
        let (conn, ldap) = LdapConnAsync::from_url_with_settings(settings, &self.url)
            .await
            .map_err(|_| ad_failed("LDAPS connection"))?;
        tokio::spawn(async move {
            let _ = conn.drive().await;
        });
        Ok(ldap)
    }

    async fn service(&self) -> Result<Ldap, Failure> {
        let mut ldap = self.connect().await?;
        ldap.with_timeout(IO_TIMEOUT)
            .simple_bind(&self.bind_dn, &self.bind_password)
            .await
            .and_then(ldap3::LdapResult::success)
            .map_err(|_| ad_failed("AD bind"))?;
        Ok(ldap)
    }

    /// Check a user's password on a separate connection.
    async fn bind_as(&self, dn: &str, password: &str) -> Result<BindOutcome, Failure> {
        if password.is_empty() {
            return Ok(BindOutcome::Rejected);
        }
        let mut ldap = self.connect().await?;
        let result = ldap
            .with_timeout(IO_TIMEOUT)
            .simple_bind(dn, password)
            .await
            .map_err(|_| ad_failed("AD user bind"))?;
        let _ = ldap.with_timeout(IO_TIMEOUT).unbind().await;
        Ok(match result.rc {
            0 => BindOutcome::Valid,
            // AD sub-codes: password expired, or must change at next logon.
            49 if result.text.contains("data 532") || result.text.contains("data 773") => {
                BindOutcome::Expired
            }
            49 => BindOutcome::Rejected,
            _ => return Err(ad_failed("AD user bind")),
        })
    }

    async fn find(&self, ldap: &mut Ldap, name: &str) -> Result<Option<Account>, Failure> {
        let filter = format!(
            "(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))",
            ldap3::ldap_escape(name)
        );
        let (entries, _) = ldap
            .with_timeout(IO_TIMEOUT)
            .search(
                &self.base_dn,
                Scope::Subtree,
                &filter,
                [
                    "description",
                    "userAccountControl",
                    "objectSid",
                    "adminCount",
                ],
            )
            .await
            .and_then(ldap3::SearchResult::success)
            .map_err(|_| ad_failed("AD user search"))?;
        let mut entries = entries.into_iter().filter(|entry| !entry.is_ref());
        let (first, second) = (entries.next(), entries.next());
        if second.is_some() {
            return Err(ad_failed("AD user search returned several accounts"));
        }
        Ok(first.map(|entry| {
            let entry = SearchEntry::construct(entry);
            Account {
                description: attribute(&entry, "description").map(str::to_owned),
                flags: attribute(&entry, "userAccountControl").and_then(|v| v.parse().ok()),
                rid: binary_attribute(&entry, "objectSid").and_then(rid),
                privileged: attribute(&entry, "adminCount").is_some_and(|v| v != "0"),
                dn: entry.dn,
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OU: &str = "OU=RDP,DC=ad,DC=example,DC=com";
    const SERVICE: &str = "CN=svc,CN=Users,DC=ad,DC=example,DC=com";

    fn identity(email: &str) -> Identity {
        Identity::new(email.into(), "test:alice".into()).unwrap()
    }

    fn account(dn: &str, description: Option<&str>, rid: u32) -> Account {
        Account {
            dn: dn.into(),
            description: description.map(str::to_owned),
            flags: Some(512),
            rid: Some(rid),
            privileged: false,
        }
    }

    #[test]
    fn primary_domain_uses_the_login_and_external_users_carry_their_domain() {
        let naming = Naming::new("Example.com", true);
        let login = |email: &str| naming.account(&identity(email)).map(|n| n.login);
        assert_eq!(
            login("Jan.Prasil@EXAMPLE.com").as_deref(),
            Some("jan.prasil")
        );
        assert_eq!(
            login("abcdefghijklmnopqrs.tuvw@example.com").as_deref(),
            Some("abcdefghijklmnopqrs")
        );
        assert_eq!(login("jan@other.cz").as_deref(), Some("jan_other_cz"));
        // An external administrator is an ordinary account.
        let external = login("administrator@other.cz").unwrap();
        assert!(!is_manual_only(&external));

        let long = naming
            .account(&identity("jan.prasil@jina-domena.cz"))
            .unwrap();
        assert_eq!(long.full, "jan.prasil_jina-domena_cz");
        assert_eq!(long.login.len(), 20);
        assert!(long.login.starts_with("jan.prasil_ji-"));
        assert_ne!(long.login, login("jan.prasil@jina-domena.com").unwrap());
        // A subdomain is not the primary domain.
        assert_eq!(
            login("jan@a.example.com").as_deref(),
            Some("jan_a_example_com")
        );
        assert!(login("jan+rdp@example.com").is_none());
        assert!(login("..@example.com").is_none());

        let closed = Naming::new("example.com", false);
        assert!(closed.account(&identity("jan@other.cz")).is_none());
        assert!(closed.account(&identity("jan@example.com")).is_some());
    }

    #[test]
    fn only_marked_accounts_in_the_dedicated_ou_are_managed() {
        let kind = |a: Account| classify(&a, "test:alice", OU, SERVICE);
        let inside = format!("CN=alice,{OU}");
        let outside = "CN=alice,CN=Users,DC=ad,DC=example,DC=com";
        assert_eq!(
            kind(account(&inside, Some("test:alice"), 1105)),
            Kind::Managed { pending: false }
        );
        assert_eq!(
            kind(account(&inside, Some("test:alice:pending"), 1105)),
            Kind::Managed { pending: true }
        );
        assert_eq!(
            kind(account(&inside, Some("test:bob"), 1105)),
            Kind::OtherOwner
        );
        assert_eq!(kind(account(&inside, None, 1105)), Kind::OtherOwner);
        // A matching marker outside the OU must not allow a password reset.
        assert_eq!(
            kind(account(outside, Some("test:alice"), 1105)),
            Kind::Existing
        );
    }

    #[test]
    fn built_in_accounts_are_protected_even_when_renamed() {
        let kind = |a: Account| classify(&a, "test:alice", OU, SERVICE);
        let renamed = format!("CN=alice,{OU}");
        assert_eq!(
            kind(account(&renamed, Some("test:alice"), RID_ADMINISTRATOR)),
            Kind::ManualOnly
        );
        assert_eq!(kind(account(&renamed, None, RID_KRBTGT)), Kind::Blocked);
        assert_eq!(kind(account(&renamed, None, RID_GUEST)), Kind::Blocked);
        assert_eq!(
            kind(account(&SERVICE.to_ascii_uppercase(), None, 1200)),
            Kind::Blocked
        );
    }

    #[tokio::test]
    async fn administrator_and_blocked_names_never_reach_the_directory() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // The directory is unreachable and there is no store: any access fails.
        let directory = Directory {
            url: Url::parse("ldaps://127.0.0.1:1").unwrap(),
            tls: Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth(),
            ),
            bind_dn: SERVICE.into(),
            bind_password: "unused".into(),
            users_ou: OU.into(),
            base_dn: domain_base(OU).unwrap(),
            rdp_group: "CN=g".into(),
            admin_group: None,
            domain: "ad.example.com".into(),
            naming: Naming::new("example.com", true),
        };
        let admin = identity("Administrator@example.com");
        let Err(Failure::NeedPassword(_)) =
            directory.credentials(&admin, None, None, None, false).await
        else {
            panic!("expected a password prompt");
        };
        let Ok((name, password)) = directory
            .credentials(&admin, None, Some("typed".into()), None, false)
            .await
        else {
            panic!("expected the typed password to be used");
        };
        assert_eq!(
            (name.as_str(), password.as_str()),
            ("administrator", "typed")
        );
        // Not even the owner may change the administrator password here.
        let Err(Failure::Refused(status, _)) = directory
            .credentials(&admin, None, Some("old".into()), Some("new".into()), false)
            .await
        else {
            panic!("expected the change to be refused");
        };
        assert_eq!(status, StatusCode::FORBIDDEN);
        for email in ["krbtgt@example.com", "Guest@example.com"] {
            let Err(Failure::Refused(status, _)) = directory
                .credentials(&identity(email), None, Some("typed".into()), None, false)
                .await
            else {
                panic!("expected {email} to be refused");
            };
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
    }

    #[test]
    fn administrators_cannot_hand_over_their_password() {
        let mut user = identity("jan@example.com");
        let record = Record::new("jan", "secret", Mode::Stored);
        assert!(record.allows_takeover(&user, "jan"));
        assert!(!record.allows_takeover(&user, "eva"));
        let privileged = Record {
            privileged: true,
            ..record.clone()
        };
        assert!(!privileged.allows_takeover(&user, "jan"));
        user.admin = true;
        assert!(!record.allows_takeover(&user, "jan"));
    }

    #[test]
    fn derives_domain_base_and_sid_suffix() {
        assert_eq!(domain_base(OU).as_deref(), Some("DC=ad,DC=example,DC=com"));
        assert!(domain_base("OU=RDP").is_none());
        assert_eq!(rid(&[1, 5, 0, 0, 244, 1, 0, 0]), Some(500));
        assert!(rid(&[1]).is_none());
    }

    #[test]
    fn generated_passwords_include_all_four_character_classes() {
        for _ in 0..32 {
            let password = generate_password();
            assert_eq!(password.len(), 24);
            assert!(password.bytes().any(|ch| ch.is_ascii_uppercase()));
            assert!(password.bytes().any(|ch| ch.is_ascii_lowercase()));
            assert!(password.bytes().any(|ch| ch.is_ascii_digit()));
            assert!(password.bytes().any(|ch| ch.is_ascii_punctuation()));
        }
    }
}
