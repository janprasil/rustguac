use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{header, uri::Authority, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::{body::Body, Extension, Json};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use ldap3::{LdapConnAsync, LdapConnSettings, Mod, Scope, SearchEntry};
use rand::{seq::SliceRandom, RngExt};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;

use crate::api::{AppState, VaultCell};
use crate::auth::AuthIdentity;
use crate::perms::{Perm, PermSet};
use crate::session::{CreateSessionRequest, SessionStatus, SessionType};

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const JWT_HEADER: &str = "cf-access-jwt-assertion";
const APP_PAGE: &str = include_str!("rdp_launch.html");

struct Access {
    issuer: String,
    tenant: Uuid,
    role: String,
    http: reqwest::Client,
    keys: Mutex<KeyCache>,
}

#[derive(Default)]
struct KeyCache {
    keys: Option<JwkSet>,
    refreshed: Option<Instant>,
    attempted: Option<Instant>,
}

#[derive(Deserialize)]
struct Claims {
    email: String,
    sub: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    custom: Option<EntraClaims>,
}

#[derive(Deserialize)]
struct EntraClaims {
    #[serde(default)]
    roles: Vec<String>,
    oid: Uuid,
    tid: Uuid,
}

#[derive(Clone)]
pub(crate) struct Identity {
    email: String,
    owner: String,
    fingerprint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetConfig {
    public_host: String,
    target_host: String,
    access_aud: String,
    connect_to: Option<String>,
    label: Option<String>,
}

struct RdpTarget {
    public_host: Option<String>,
    host: String,
    validation: Validation,
    connect_to: Option<String>,
    label: String,
}

enum Targets {
    Single(Arc<RdpTarget>),
    ByHostname(HashMap<String, HashMap<Option<String>, Arc<RdpTarget>>>),
}

#[derive(Clone)]
pub(crate) struct AuthorizedTarget {
    identity: Identity,
    target: Arc<RdpTarget>,
}

impl AuthorizedTarget {
    fn session_owner(&self) -> String {
        match (&self.target.public_host, &self.target.connect_to) {
            (Some(host), Some(target)) => format!("{}@{host}/{target}", self.identity.owner),
            (Some(host), None) => format!("{}@{host}", self.identity.owner),
            (None, _) => self.identity.owner.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct QuickConnectTargets(Vec<Arc<RdpTarget>>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManualLogin {
    password: String,
}

impl Identity {
    fn windows_login(&self) -> Option<&str> {
        let (login, _) = self.email.split_once('@')?;
        ((1..=20).contains(&login.len())
            && login
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'.' | b'_' | b'-')))
        .then_some(login)
    }
}

struct Directory {
    url: Url,
    tls: Arc<rustls::ClientConfig>,
    bind_dn: String,
    bind_password: String,
    users_ou: String,
    rdp_group: String,
    domain: String,
}

pub struct RdpSso {
    access: Access,
    directory: Directory,
    targets: Targets,
    ignore_cert: bool,
    launch_locks: [Mutex<()>; 64],
}

fn required(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is required"))
}

fn flag(name: &str) -> Result<bool, String> {
    match std::env::var(name).as_deref() {
        Ok("true") => Ok(true),
        Ok("false") | Err(std::env::VarError::NotPresent) => Ok(false),
        _ => Err(format!("{name} must be true or false")),
    }
}

impl RdpSso {
    pub fn from_env() -> Result<Option<Arc<Self>>, String> {
        if !flag("CF_RDP_SSO")? {
            return Ok(None);
        }

        let url = Url::parse(&required("CF_ACCESS_TEAM_DOMAIN")?)
            .map_err(|_| "CF_ACCESS_TEAM_DOMAIN must be an HTTPS origin")?;
        if url.scheme() != "https"
            || url.as_str() != format!("{}/", url.origin().ascii_serialization())
        {
            return Err("CF_ACCESS_TEAM_DOMAIN must be an HTTPS origin".into());
        }
        let issuer = url.origin().ascii_serialization();
        let tenant = required("CF_ENTRA_TENANT_ID")?
            .parse()
            .map_err(|_| "CF_ENTRA_TENANT_ID must be a UUID")?;
        let role = required("CF_REQUIRED_ROLE")?;
        let targets = Targets::from_env(&issuer)?;
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(IO_TIMEOUT)
            .build()
            .map_err(|_| "Could not configure Cloudflare JWKS client")?;
        Ok(Some(Arc::new(Self {
            access: Access {
                issuer,
                tenant,
                role,
                http,
                keys: Mutex::new(KeyCache::default()),
            },
            directory: Directory::from_env()?,
            targets,
            ignore_cert: flag("RDP_IGNORE_CERT")?,
            launch_locks: std::array::from_fn(|_| Mutex::new(())),
        })))
    }
}

impl RdpTarget {
    fn new(public_host: Option<String>, host: String, issuer: &str, audience: &str) -> Self {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["aud", "iss", "exp", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = 0;
        Self {
            public_host,
            label: host.clone(),
            host,
            validation,
            connect_to: None,
        }
    }
}

impl Targets {
    fn from_env(issuer: &str) -> Result<Self, String> {
        match std::env::var("RDP_TARGETS") {
            Ok(value) if !value.trim().is_empty() => Self::parse(&value, issuer),
            Ok(_) | Err(std::env::VarError::NotPresent) => {
                let host = required("RDP_TARGET_HOST")?;
                let audience = required("CF_ACCESS_AUD")?;
                Ok(Self::Single(Arc::new(RdpTarget::new(
                    None, host, issuer, &audience,
                ))))
            }
            Err(_) => Err("RDP_TARGETS must be valid UTF-8".into()),
        }
    }

    fn parse(value: &str, issuer: &str) -> Result<Self, String> {
        let configs: Vec<TargetConfig> = serde_json::from_str(value)
            .map_err(|err| format!("RDP_TARGETS must be a JSON array of RDP targets: {err}"))?;
        if configs.is_empty() {
            return Err("RDP_TARGETS must contain at least one server".into());
        }

        let mut targets: HashMap<String, HashMap<Option<String>, Arc<RdpTarget>>> = HashMap::new();
        for (index, config) in configs.into_iter().enumerate() {
            let name = config.public_host.to_ascii_lowercase();
            if !name.contains('.')
                || !valid_dns_hostname(&name)
                || !valid_rdp_host(&config.target_host)
                || config
                    .connect_to
                    .as_deref()
                    .is_some_and(|name| !valid_rdp_host(name))
                || config.access_aud.is_empty()
                || config.access_aud.chars().any(char::is_whitespace)
            {
                return Err(format!(
                    "Invalid hostname, target, or audience in RDP_TARGETS entry {}",
                    index + 1
                ));
            }
            let mut target = RdpTarget::new(
                Some(name.clone()),
                config.target_host,
                issuer,
                &config.access_aud,
            );
            target.connect_to = config.connect_to;
            if let Some(label) = config.label {
                if label.trim().is_empty()
                    || label.chars().count() > 100
                    || label.chars().any(char::is_control)
                {
                    return Err(format!("Invalid label in RDP_TARGETS entry {}", index + 1));
                }
                target.label = label;
            }
            let by_selector = targets.entry(name.clone()).or_default();
            if by_selector
                .values()
                .next()
                .is_some_and(|existing| existing.validation.aud != target.validation.aud)
            {
                return Err(format!(
                    "RDP_TARGETS entries for {name} must use the same access_aud"
                ));
            }
            if by_selector
                .insert(target.connect_to.clone(), Arc::new(target))
                .is_some()
            {
                return Err(format!(
                    "Duplicate public_host and connect_to in RDP_TARGETS for {name}"
                ));
            }
        }
        Ok(Self::ByHostname(targets))
    }

    fn for_request(&self, request: &Request) -> Option<&Arc<RdpTarget>> {
        let mut selectors =
            url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
                .filter(|(key, _)| key == "connectTo");
        let selector = selectors.next().map(|(_, value)| value.into_owned());
        if selectors.next().is_some() {
            return None;
        }
        match self {
            Self::Single(target) => selector.is_none().then_some(target),
            Self::ByHostname(targets) => targets.get(&request_hostname(request)?)?.get(&selector),
        }
    }

    fn menu(&self, request: &Request) -> Option<QuickConnectTargets> {
        let mut targets: Vec<_> = match self {
            Self::Single(target) => vec![target.clone()],
            Self::ByHostname(targets) => targets
                .get(&request_hostname(request)?)?
                .values()
                .cloned()
                .collect(),
        };
        targets.sort_by(|a, b| (&a.label, &a.connect_to).cmp(&(&b.label, &b.connect_to)));
        Some(QuickConnectTargets(targets))
    }
}

fn request_hostname(request: &Request) -> Option<String> {
    if let Some(host) = request.uri().authority() {
        return Some(host.host().to_ascii_lowercase());
    }
    let host = request
        .headers()
        .get(header::HOST)?
        .to_str()
        .ok()?
        .parse::<Authority>()
        .ok()?;
    Some(host.host().to_ascii_lowercase())
}

fn query_has(uri: &axum::http::Uri, name: &str) -> bool {
    uri.query().is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key == name)
    })
}

fn valid_rdp_host(host: &str) -> bool {
    valid_dns_hostname(host) || host.parse::<IpAddr>().is_ok()
}

fn valid_dns_hostname(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == b'-')
        })
}

impl Access {
    async fn authenticate(
        &self,
        headers: &HeaderMap,
        validation: &Validation,
    ) -> Result<Identity, (StatusCode, &'static str)> {
        let invalid = (
            StatusCode::UNAUTHORIZED,
            "A valid Cloudflare Access session is required.",
        );
        let forbidden = (
            StatusCode::FORBIDDEN,
            "Your Entra account does not have Remote Desktop access.",
        );
        let token = headers
            .get(JWT_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or(invalid)?;
        let jwt = decode_header(token).map_err(|_| invalid)?;
        let kid = jwt
            .kid
            .filter(|_| jwt.alg == Algorithm::RS256)
            .ok_or(invalid)?;

        let key = {
            let mut cache = self.keys.lock().await;
            let fresh = cache
                .refreshed
                .is_some_and(|time| time.elapsed() < Duration::from_secs(3600));
            let known = cache
                .keys
                .as_ref()
                .is_some_and(|keys| keys.find(&kid).is_some());
            let can_refresh = cache
                .attempted
                .is_none_or(|time| time.elapsed() >= Duration::from_secs(10));
            if (!fresh || !known) && can_refresh {
                cache.attempted = Some(Instant::now());
                if let Ok(response) = self
                    .http
                    .get(format!("{}/cdn-cgi/access/certs", self.issuer))
                    .send()
                    .await
                {
                    if let Ok(response) = response.error_for_status() {
                        if let Ok(keys) = response.json::<JwkSet>().await {
                            cache.keys = Some(keys);
                            cache.refreshed = Some(Instant::now());
                        }
                    }
                }
            }
            if cache
                .refreshed
                .is_none_or(|time| time.elapsed() >= Duration::from_secs(3600))
            {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Cloudflare Access verification is temporarily unavailable.",
                ));
            }
            let key = cache
                .keys
                .as_ref()
                .and_then(|keys| keys.find(&kid))
                .ok_or(invalid)?;
            DecodingKey::try_from(key).map_err(|_| invalid)?
        };

        let claims = decode::<Claims>(token, &key, validation)
            .map_err(|_| invalid)?
            .claims;
        claims
            .into_identity(self.tenant, &self.role)
            .ok_or(forbidden)
    }
}

impl Claims {
    fn into_identity(self, tenant: Uuid, role: &str) -> Option<Identity> {
        let entra = self.custom?;
        if self.kind != "app"
            || self.sub.is_empty()
            || entra.tid != tenant
            || !entra.roles.iter().any(|value| value == role)
        {
            return None;
        }
        let (login, domain) = self.email.split_once('@')?;
        if login.is_empty()
            || domain.is_empty()
            || domain.contains('@')
            || self.email.len() > 254
            || self
                .email
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return None;
        }
        let owner = format!("entra:{}:{}", entra.tid, entra.oid);
        let fingerprint = hex::encode(Sha256::digest(owner.as_bytes()));
        Some(Identity {
            email: self.email,
            owner,
            fingerprint,
        })
    }
}

impl Directory {
    fn from_env() -> Result<Self, String> {
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
        Ok(Self {
            url,
            tls: Arc::new(tls),
            bind_dn: required("AD_BIND_DN")?,
            bind_password: required("AD_BIND_PASSWORD")?,
            users_ou: required("AD_USERS_OU")?,
            rdp_group: required("AD_RDP_GROUP_DN")?,
            domain: required("AD_DOMAIN")?,
        })
    }

    async fn rotate_password(
        &self,
        identity: &Identity,
        password: &str,
    ) -> Result<String, &'static str> {
        let settings = LdapConnSettings::new()
            .set_conn_timeout(IO_TIMEOUT)
            .set_config(self.tls.clone());
        let (conn, mut ldap) = LdapConnAsync::from_url_with_settings(settings, &self.url)
            .await
            .map_err(|_| "LDAPS connection")?;
        tokio::spawn(async move {
            let _ = conn.drive().await;
        });
        checked(
            ldap.with_timeout(IO_TIMEOUT)
                .simple_bind(&self.bind_dn, &self.bind_password)
                .await,
            "AD bind",
        )?;

        let cn = format!("rustguac-{}", &identity.fingerprint[..32]);
        let dn = format!("CN={cn},{}", self.users_ou);
        let pending = format!("{}:pending", identity.owner);
        let attrs = ["description", "sAMAccountName", "userAccountControl"];
        let result = ldap
            .with_timeout(IO_TIMEOUT)
            .search(&dn, Scope::Base, "(objectClass=user)", attrs)
            .await
            .map_err(|_| "AD user search")?;
        let (username, enable) = if result.1.rc == 32 {
            let username = account_name(identity);
            let upn = format!("{username}@{}", self.domain);
            checked(
                ldap.with_timeout(IO_TIMEOUT)
                    .add(
                        &dn,
                        vec![
                            ("objectClass", HashSet::from(["user"])),
                            ("cn", HashSet::from([cn.as_str()])),
                            ("sAMAccountName", HashSet::from([username.as_str()])),
                            ("userPrincipalName", HashSet::from([upn.as_str()])),
                            ("mail", HashSet::from([identity.email.as_str()])),
                            ("displayName", HashSet::from([identity.email.as_str()])),
                            ("userAccountControl", HashSet::from(["514"])),
                            ("description", HashSet::from([pending.as_str()])),
                        ],
                    )
                    .await,
                "AD user creation",
            )?;
            (username, true)
        } else {
            let (entries, _) = result.success().map_err(|_| "AD user search")?;
            let [entry] = entries.as_slice() else {
                return Err("AD user ownership");
            };
            let entry = SearchEntry::construct(entry.clone());
            let marker = attribute(&entry, "description").ok_or("AD user ownership")?;
            let enable = marker == pending;
            if !enable && marker != identity.owner {
                return Err("AD user ownership");
            }
            let username = attribute(&entry, "sAMAccountName")
                .filter(|name| valid_account_name(name, &identity.fingerprint))
                .ok_or("AD username")?;
            let flags = attribute(&entry, "userAccountControl")
                .and_then(|flags| flags.parse::<u32>().ok())
                .ok_or("AD account flags")?;
            if (enable && flags != 514) || (!enable && (flags & 514) != 512) {
                return Err("AD account disabled or unsuitable");
            }
            (username.to_owned(), enable)
        };

        let group = ldap
            .with_timeout(IO_TIMEOUT)
            .modify(
                &self.rdp_group,
                vec![Mod::Add("member", HashSet::from([dn.as_str()]))],
            )
            .await
            .map_err(|_| "AD RDP group membership")?;
        if !matches!(group.rc, 0 | 20) {
            return Err("AD RDP group membership");
        }
        let unicode_password: Vec<u8> = format!("\"{password}\"")
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        checked(
            ldap.with_timeout(IO_TIMEOUT)
                .modify(
                    &dn,
                    vec![Mod::Replace(
                        b"unicodePwd".to_vec(),
                        HashSet::from([unicode_password]),
                    )],
                )
                .await,
            "AD password rotation",
        )?;
        if enable {
            checked(
                ldap.with_timeout(IO_TIMEOUT)
                    .modify(
                        &dn,
                        vec![
                            Mod::Replace("userAccountControl", HashSet::from(["512"])),
                            Mod::Replace("description", HashSet::from([identity.owner.as_str()])),
                        ],
                    )
                    .await,
                "AD account activation",
            )?;
        }
        let _ = ldap.with_timeout(IO_TIMEOUT).unbind().await;
        Ok(username)
    }
}

fn checked(
    result: Result<ldap3::LdapResult, ldap3::LdapError>,
    step: &'static str,
) -> Result<(), &'static str> {
    result
        .and_then(ldap3::LdapResult::success)
        .map(|_| ())
        .map_err(|_| step)
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

fn account_name(identity: &Identity) -> String {
    let prefix: String = identity
        .email
        .split('@')
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
        .take(7)
        .map(|ch| ch.to_ascii_lowercase())
        .collect();
    format!("{prefix}-{}", &identity.fingerprint[..12])
}

fn valid_account_name(name: &str, fingerprint: &str) -> bool {
    (13..=20).contains(&name.len())
        && name.ends_with(&format!("-{}", &fingerprint[..12]))
        && name
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'.' | b'_' | b'-'))
}

fn generate_password() -> String {
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

pub async fn authenticate(
    State(sso): State<Arc<RdpSso>>,
    mut request: Request,
    next: Next,
) -> Response {
    let uri = request.uri();
    let wants_menu = request.method() == axum::http::Method::GET
        && uri.path() == "/"
        && query_has(uri, "quickConnect")
        && !query_has(uri, "connectTo");
    let menu = wants_menu.then(|| sso.targets.menu(&request)).flatten();
    let target = if wants_menu {
        menu.as_ref().and_then(|menu| menu.0.first())
    } else {
        sso.targets.for_request(&request)
    };
    let Some(target) = target.cloned() else {
        return (
            StatusCode::NOT_FOUND,
            "No Remote Desktop is configured for this address and target.",
        )
            .into_response();
    };
    let identity = match sso
        .access
        .authenticate(request.headers(), &target.validation)
        .await
    {
        Ok(identity) => identity,
        Err((status, message)) => {
            if request.method() == axum::http::Method::GET
                && matches!(request.uri().path(), "/" | "/connections.html")
            {
                return (status, Html(format!("<!doctype html><meta charset=utf-8><title>Remote Desktop</title><p>{message}</p>"))).into_response();
            }
            return (status, message).into_response();
        }
    };
    let authorized = AuthorizedTarget { identity, target };
    request.extensions_mut().insert(AuthIdentity::User {
        email: authorized.session_owner(),
        role: "rdp-sso".into(),
        groups: Vec::new(),
        roles: Vec::new(),
        perms: PermSet::of(&[Perm::ConnectionsConnect]),
    });
    request.extensions_mut().insert(authorized);
    if let Some(menu) = menu {
        request.extensions_mut().insert(menu);
    }
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

pub(crate) async fn index(
    Extension(authorized): Extension<AuthorizedTarget>,
    menu: Option<Extension<QuickConnectTargets>>,
    uri: axum::http::Uri,
) -> impl IntoResponse {
    let auto = menu.is_none() && uri.path() == "/";
    let mut buttons = String::new();
    let targets = menu.as_ref().map_or_else(
        || std::slice::from_ref(&authorized.target),
        |Extension(menu)| menu.0.as_slice(),
    );
    for target in targets {
        use std::fmt::Write;
        let selector = crate::html_escape(target.connect_to.as_deref().unwrap_or_default());
        let label = crate::html_escape(&target.label);
        let _ = write!(
            buttons,
            r#"<li><button type="button" data-target="{selector}">{label}</button></li>"#
        );
    }
    let page = APP_PAGE
        .replace("@@AUTO@@", if auto { "true" } else { "false" })
        .replace(
            "@@USERNAME@@",
            &crate::html_escape(authorized.identity.windows_login().unwrap_or_default()),
        )
        .replace("@@TARGETS@@", &buttons);
    Html(page)
}

pub async fn launch(
    State(manager): State<AppState>,
    Extension(sso): Extension<Arc<RdpSso>>,
    Extension(vault): Extension<VaultCell>,
    Extension(authorized): Extension<AuthorizedTarget>,
    headers: HeaderMap,
    manual: Option<Json<ManualLogin>>,
) -> Response {
    // A cross-origin form cannot supply this header.
    if headers
        .get("x-rustguac-launch")
        .is_none_or(|value| value != "1")
    {
        return (
            StatusCode::FORBIDDEN,
            "Remote Desktop must be opened from this site.",
        )
            .into_response();
    }
    let manual = manual.map(|Json(login)| login);
    // Finish provisioning even if the browser disconnects during the request.
    match tokio::spawn(launch_session(manager, sso, vault, authorized, manual)).await {
        Ok(response) => response,
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not open the Remote Desktop session.",
        )
            .into_response(),
    }
}

async fn launch_session(
    manager: AppState,
    sso: Arc<RdpSso>,
    vault: VaultCell,
    authorized: AuthorizedTarget,
    manual: Option<ManualLogin>,
) -> Response {
    let identity = &authorized.identity;
    let session_owner = authorized.session_owner();
    let shard = usize::from_str_radix(&identity.fingerprint[..2], 16).unwrap_or_default()
        % sso.launch_locks.len();
    let _lock = sso.launch_locks[shard].lock().await;

    let mut live_username = None;
    for session in manager.list_sessions().await {
        let (account, _) = session
            .created_by
            .split_once('@')
            .unwrap_or((&session.created_by, ""));
        if account != identity.owner {
            continue;
        }
        let same_target = session.created_by == session_owner;
        match session.status {
            SessionStatus::Pending if same_target && manual.is_none() => {
                return launch_response(session.client_url, &authorized.target)
            }
            SessionStatus::Pending if same_target => {
                return (
                    StatusCode::CONFLICT,
                    "A connection is still starting. Try again once it has closed.",
                )
                    .into_response();
            }
            SessionStatus::Active if same_target => {
                return (
                    StatusCode::CONFLICT,
                    "Remote Desktop is already open in another tab.",
                )
                    .into_response()
            }
            SessionStatus::Pending | SessionStatus::Active
                if valid_account_name(&session.username, &identity.fingerprint) =>
            {
                live_username = Some(session.username)
            }
            _ => {}
        }
    }

    let credentials = match manual {
        Some(login) => {
            let username = identity
                .windows_login()
                .filter(|name| !valid_account_name(name, &identity.fingerprint));
            match username {
                Some(username) if !login.password.is_empty() && login.password.len() <= 1024 => {
                    Ok((username.to_owned(), login.password))
                }
                _ => Err((
                    StatusCode::BAD_REQUEST,
                    "A valid Windows login and password are required.",
                )),
            }
        }
        None => automatic_credentials(identity, &sso.directory, &vault, live_username).await,
    };
    let (username, password) = match credentials {
        Ok(credentials) => credentials,
        Err(error) => return error.into_response(),
    };

    let req = CreateSessionRequest {
        session_type: SessionType::Rdp,
        hostname: Some(authorized.target.host.clone()),
        port: Some(3389),
        username: Some(username),
        domain: Some(sso.directory.domain.clone()),
        password: Some(password),
        security: Some("nla".into()),
        ignore_cert: Some(sso.ignore_cert),
        ..Default::default()
    };
    match manager.create_session(req, session_owner).await {
        Ok(session) => launch_response(session.client_url, &authorized.target),
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            "Could not open the Remote Desktop session.",
        )
            .into_response(),
    }
}

async fn automatic_credentials(
    identity: &Identity,
    directory: &Directory,
    vault: &VaultCell,
    live_username: Option<String>,
) -> Result<(String, String), (StatusCode, &'static str)> {
    let Some(vault) = vault.read().await.clone() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "The credential store is temporarily unavailable.",
        ));
    };
    // Keep the password valid while another desktop may still be authenticating.
    if let Some(username) = live_username {
        let path = format!("rdp-users/{username}");
        match vault.read_kv_field(&path, "password").await {
            Ok(password) => Ok((username, password)),
            Err(_) => {
                tracing::warn!("RDP password could not be read for a concurrent session");
                Err((
                    StatusCode::BAD_GATEWAY,
                    "Could not retrieve your Windows credential.",
                ))
            }
        }
    } else {
        let password = generate_password();
        let username = match directory.rotate_password(identity, &password).await {
            Ok(username) => username,
            Err(step) => {
                tracing::warn!(%step, "RDP account provisioning failed");
                return Err((
                    StatusCode::BAD_GATEWAY,
                    "Could not prepare your Windows account.",
                ));
            }
        };
        if vault.put_rdp_password(&username, &password).await.is_err() {
            tracing::warn!("RDP password could not be stored");
            return Err((
                StatusCode::BAD_GATEWAY,
                "Could not store your Windows credential.",
            ));
        }
        Ok((username, password))
    }
}

fn launch_response(mut url: String, target: &RdpTarget) -> Response {
    url.push_str("?rdpSso=1");
    if let Some(selector) = &target.connect_to {
        url.push_str("&connectTo=");
        url.push_str(&urlencoding::encode(selector));
    }
    Response::new(Body::from(url))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(email: &str, tenant: Uuid, object_id: Uuid) -> Claims {
        serde_json::from_value(serde_json::json!({
            "type": "app",
            "sub": "access-user",
            "email": email,
            "custom": { "tid": tenant, "oid": object_id, "roles": ["RemoteDesktop", "AnotherRole"] },
        }))
        .unwrap()
    }

    #[test]
    fn only_the_expected_role_and_tenant_grant_access() {
        let tenant = Uuid::new_v4();
        let oid = Uuid::new_v4();
        assert!(claims("user@example.com", tenant, oid)
            .into_identity(tenant, "RemoteDesktop")
            .is_some());
        assert!(claims("user@example.com", tenant, oid)
            .into_identity(tenant, "Remote")
            .is_none());
        assert!(claims("user@example.com", tenant, oid)
            .into_identity(Uuid::new_v4(), "RemoteDesktop")
            .is_none());
        let mut missing = claims("user@example.com", tenant, oid);
        missing.custom = None;
        assert!(missing.into_identity(tenant, "RemoteDesktop").is_none());
    }

    #[test]
    fn account_ownership_survives_email_changes() {
        let tenant = Uuid::new_v4();
        let oid = Uuid::new_v4();
        let original = claims("VeryLongLogin@example.com", tenant, oid)
            .into_identity(tenant, "RemoteDesktop")
            .unwrap();
        let renamed = claims("different@example.com", tenant, oid)
            .into_identity(tenant, "RemoteDesktop")
            .unwrap();
        let namesake = claims("VeryLongLogin@example.org", tenant, Uuid::new_v4())
            .into_identity(tenant, "RemoteDesktop")
            .unwrap();

        let username = account_name(&original);
        assert_eq!(username.len(), 20);
        assert_eq!(original.owner, renamed.owner);
        assert!(valid_account_name(&username, &renamed.fingerprint));
        assert!(!valid_account_name(&username, &namesake.fingerprint));
        assert_ne!(username, account_name(&namesake));
    }

    const TWO_TARGETS: &str = r#"[
        {"public_host":"rdp-1.example.com","target_host":"windows-1.local","access_aud":"aud-1"},
        {"public_host":"rdp-2.example.com","target_host":"10.0.0.12","access_aud":"aud-2"}
    ]"#;

    fn request_for(host: &str) -> Request {
        Request::builder()
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn maps_hostname_to_target_and_access_audience() {
        let targets = Targets::parse(TWO_TARGETS, "https://access.example.com").unwrap();
        let first = targets
            .for_request(&request_for("RDP-1.example.com:443"))
            .unwrap();
        let second = targets
            .for_request(&request_for("rdp-2.example.com"))
            .unwrap();
        assert_eq!(first.host, "windows-1.local");
        assert_eq!(second.host, "10.0.0.12");
        assert_eq!(first.validation.aud, Some(HashSet::from(["aud-1".into()])));
        assert_eq!(second.validation.aud, Some(HashSet::from(["aud-2".into()])));
        assert!(targets
            .for_request(&request_for("unknown.example.com"))
            .is_none());
    }

    #[test]
    fn connect_to_only_selects_configured_targets() {
        let targets = Targets::parse(
            r#"[
                {"public_host":"autordp.example.com","connect_to":"10.0.0.1","target_host":"server-1","access_aud":"aud"},
                {"public_host":"autordp.example.com","connect_to":"10.0.0.2","target_host":"server-2","access_aud":"aud"}
            ]"#,
            "https://access.example.com",
        ).unwrap();
        let lookup = |query| {
            let mut request = request_for("autordp.example.com");
            *request.uri_mut() = format!("/?{query}").parse().unwrap();
            targets.for_request(&request)
        };
        assert_eq!(lookup("connectTo=10.0.0.1").unwrap().host, "server-1");
        assert_eq!(lookup("connectTo=10.0.0.2").unwrap().host, "server-2");
        assert!(lookup("connectTo=10.0.0.3").is_none());
        assert!(lookup("").is_none());
        assert!(lookup("connectTo=10.0.0.1&connectTo=10.0.0.2").is_none());
    }

    #[test]
    fn rejects_duplicate_public_hostnames_and_url_targets() {
        let duplicate = TWO_TARGETS.replace("rdp-2", "RDP-1");
        let invalid_target = TWO_TARGETS.replace("windows-1.local", "rdp://windows-1.local");
        assert!(Targets::parse(&duplicate, "https://access.example.com").is_err());
        assert!(Targets::parse(&invalid_target, "https://access.example.com").is_err());
    }

    #[test]
    fn session_ownership_is_bound_to_the_public_hostname() {
        let targets = Targets::parse(TWO_TARGETS, "https://access.example.com").unwrap();
        let tenant = Uuid::new_v4();
        let identity = claims("user@example.com", tenant, Uuid::new_v4())
            .into_identity(tenant, "RemoteDesktop")
            .unwrap();
        let first = AuthorizedTarget {
            identity: identity.clone(),
            target: targets
                .for_request(&request_for("rdp-1.example.com"))
                .unwrap()
                .clone(),
        };
        let second = AuthorizedTarget {
            identity,
            target: targets
                .for_request(&request_for("rdp-2.example.com"))
                .unwrap()
                .clone(),
        };
        assert_ne!(first.session_owner(), second.session_owner());
        assert_eq!(first.identity.fingerprint, second.identity.fingerprint);
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
