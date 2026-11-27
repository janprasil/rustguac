use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, uri::Authority, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{body::Body, Extension, Json};
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::api::{AppState, VaultCell};
use crate::auth::AuthIdentity;
use crate::config::OidcConfig;
use crate::db::Db;
use crate::perms::{Perm, PermSet};
use crate::rdp_account::{Directory, Failure};
#[cfg(feature = "rdp-cloudflare-example")]
use crate::rdp_identity::cloudflare_example::CloudflareAccess;
use crate::rdp_identity::{required, Identity, IdentityProvider, NativeOidc};
use crate::session::{CreateSessionRequest, SessionStatus, SessionType};

const PROMPT_HEADER: &str = "x-rustguac-prompt";
const APP_PAGE: &str = include_str!("rdp_launch.html");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetConfig {
    public_host: String,
    target_host: String,
    access_aud: Option<String>,
    connect_to: Option<String>,
    label: Option<String>,
    /// Listed and opened only for holders of the admin role.
    #[serde(default)]
    admin: bool,
}

struct RdpTarget {
    public_host: Option<String>,
    host: String,
    audience: Option<String>,
    connect_to: Option<String>,
    label: String,
    admin: bool,
}

impl RdpTarget {
    fn allows(&self, identity: &Identity) -> bool {
        !self.admin || identity.admin
    }
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
    new_password: Option<String>,
}

pub struct RdpSso {
    identity_provider: Box<dyn IdentityProvider>,
    native_oidc: bool,
    directory: Directory,
    targets: Targets,
    ignore_cert: bool,
    launch_locks: [Mutex<()>; 64],
}

fn flag(name: &str) -> Result<bool, String> {
    match std::env::var(name).as_deref() {
        Ok("true") => Ok(true),
        Ok("false") | Err(std::env::VarError::NotPresent) => Ok(false),
        _ => Err(format!("{name} must be true or false")),
    }
}

impl RdpSso {
    pub fn from_env(oidc: Option<&OidcConfig>, db: &Db) -> Result<Option<Arc<Self>>, String> {
        let configured = std::env::var("RDP_IDENTITY_PROVIDER")
            .ok()
            .filter(|provider| !provider.is_empty());
        if configured.is_none() && !flag("CF_RDP_SSO")? {
            return Ok(None);
        }
        let provider = configured.as_deref().unwrap_or("cloudflare");
        let admin_role = required("RDP_ADMIN_ROLE").ok();
        let native_oidc = provider == "oidc";
        let identity_provider: Box<dyn IdentityProvider> =
            match provider {
                #[cfg(feature = "rdp-cloudflare-example")]
                "cloudflare" => Box::new(CloudflareAccess::from_env(admin_role.clone())?),
                #[cfg(not(feature = "rdp-cloudflare-example"))]
                "cloudflare" => return Err(
                    "Cloudflare authentication requires the rdp-cloudflare-example build feature"
                        .into(),
                ),
                "oidc" => {
                    let config =
                        oidc.ok_or("RDP_IDENTITY_PROVIDER=oidc requires [oidc] configuration")?;
                    Box::new(NativeOidc::new(db.clone(), config.issuer_url.clone()))
                }
                _ => return Err("RDP_IDENTITY_PROVIDER must be cloudflare or oidc".into()),
            };
        let targets = Targets::from_env(!native_oidc)?;
        let directory = Directory::from_env()?;
        if targets.has_admin_target()
            && (native_oidc || admin_role.is_none() || !directory.has_admin_group())
        {
            return Err(
                "Admin targets require the cloudflare provider, RDP_ADMIN_ROLE and AD_RDP_ADMIN_GROUP_DN"
                    .into(),
            );
        }
        Ok(Some(Arc::new(Self {
            identity_provider,
            native_oidc,
            directory,
            targets,
            ignore_cert: flag("RDP_IGNORE_CERT")?,
            launch_locks: std::array::from_fn(|_| Mutex::new(())),
        })))
    }

    async fn lock(&self, identity: &Identity) -> tokio::sync::MutexGuard<'_, ()> {
        let shard = usize::from_str_radix(&identity.fingerprint[..2], 16).unwrap_or_default()
            % self.launch_locks.len();
        self.launch_locks[shard].lock().await
    }

    pub fn uses_native_oidc(&self) -> bool {
        self.native_oidc
    }
}

impl RdpTarget {
    fn new(public_host: Option<String>, host: String, audience: Option<String>) -> Self {
        Self {
            public_host,
            label: host.clone(),
            host,
            audience,
            connect_to: None,
            admin: false,
        }
    }
}

impl Targets {
    fn from_env(require_audience: bool) -> Result<Self, String> {
        match std::env::var("RDP_TARGETS") {
            Ok(value) if !value.trim().is_empty() => Self::parse(&value, require_audience),
            Ok(_) | Err(std::env::VarError::NotPresent) => {
                let host = required("RDP_TARGET_HOST")?;
                let audience = require_audience
                    .then(|| required("CF_ACCESS_AUD"))
                    .transpose()?;
                Ok(Self::Single(Arc::new(RdpTarget::new(None, host, audience))))
            }
            Err(_) => Err("RDP_TARGETS must be valid UTF-8".into()),
        }
    }

    fn parse(value: &str, require_audience: bool) -> Result<Self, String> {
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
                || (require_audience && config.access_aud.is_none())
                || config.access_aud.as_deref().is_some_and(|audience| {
                    audience.is_empty() || audience.chars().any(char::is_whitespace)
                })
            {
                return Err(format!(
                    "Invalid hostname, target, or audience in RDP_TARGETS entry {}",
                    index + 1
                ));
            }
            let mut target =
                RdpTarget::new(Some(name.clone()), config.target_host, config.access_aud);
            target.connect_to = config.connect_to;
            target.admin = config.admin;
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
                .is_some_and(|existing| existing.audience != target.audience)
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

    fn has_admin_target(&self) -> bool {
        match self {
            Self::Single(target) => target.admin,
            Self::ByHostname(hosts) => hosts.values().flat_map(HashMap::values).any(|t| t.admin),
        }
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
        .identity_provider
        .authenticate(request.headers(), target.audience.as_deref())
        .await
    {
        Ok(identity) => identity,
        Err((status, message)) => {
            if request.method() == axum::http::Method::GET
                && matches!(request.uri().path(), "/" | "/connections.html")
            {
                if status == StatusCode::UNAUTHORIZED
                    && sso.uses_native_oidc()
                    && !query_has(request.uri(), "sso_error")
                {
                    let next = request
                        .uri()
                        .path_and_query()
                        .map_or("/", |uri| uri.as_str());
                    return Redirect::to(&format!(
                        "/auth/login?next={}",
                        urlencoding::encode(next)
                    ))
                    .into_response();
                }
                return (status, Html(format!("<!doctype html><meta charset=utf-8><title>Remote Desktop</title><p>{message}</p>"))).into_response();
            }
            return (status, message).into_response();
        }
    };
    // The menu is filtered per user; a direct link to a hidden target is a 404.
    let menu = menu.map(|mut menu| {
        menu.0.retain(|target| target.allows(&identity));
        menu
    });
    if menu.is_none() && !target.allows(&identity) {
        return (
            StatusCode::NOT_FOUND,
            "No Remote Desktop is configured for this address and target.",
        )
            .into_response();
    }
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
    Extension(sso): Extension<Arc<RdpSso>>,
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
            &crate::html_escape(
                &sso.directory
                    .naming
                    .account(&authorized.identity)
                    .map(|name| name.login)
                    .unwrap_or_default(),
            ),
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
    if let Some(denied) = require_same_site(&headers) {
        return denied;
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
    let _lock = sso.lock(identity).await;
    let name = sso
        .directory
        .naming
        .account(identity)
        .map(|name| name.login)
        .unwrap_or_default();

    let mut live = false;
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
            SessionStatus::Pending | SessionStatus::Active if session.username == name => {
                live = true
            }
            _ => {}
        }
    }

    let (typed, new_password) = match manual {
        Some(login) => (Some(login.password), login.new_password),
        None => (None, None),
    };
    if [&typed, &new_password]
        .into_iter()
        .flatten()
        .any(|password| password.is_empty() || password.len() > 1024)
    {
        return (StatusCode::BAD_REQUEST, "A Windows password is required.").into_response();
    }
    let vault = vault.read().await.clone();
    let (username, password) = match sso
        .directory
        .credentials(identity, vault.as_deref(), typed, new_password, live)
        .await
    {
        Ok(credentials) => credentials,
        Err(failure) => return failure_response(failure),
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

fn failure_response(failure: Failure) -> Response {
    match failure {
        Failure::NeedPassword(message) => {
            (StatusCode::CONFLICT, [(PROMPT_HEADER, "password")], message).into_response()
        }
        Failure::NeedNewPassword(message) => (
            StatusCode::CONFLICT,
            [(PROMPT_HEADER, "new-password")],
            message,
        )
            .into_response(),
        Failure::Refused(status, message) => (status, message).into_response(),
    }
}

/// Whether to offer the takeover button.
pub async fn account(
    Extension(sso): Extension<Arc<RdpSso>>,
    Extension(vault): Extension<VaultCell>,
    Extension(authorized): Extension<AuthorizedTarget>,
) -> Response {
    let Some(vault) = vault.read().await.clone() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match sso
        .directory
        .takeover_available(&authorized.identity, &vault)
        .await
    {
        Ok(takeover) => Json(serde_json::json!({ "takeover": takeover })).into_response(),
        Err(failure) => failure_response(failure),
    }
}

pub async fn take_over(
    Extension(sso): Extension<Arc<RdpSso>>,
    Extension(vault): Extension<VaultCell>,
    Extension(authorized): Extension<AuthorizedTarget>,
    headers: HeaderMap,
) -> Response {
    if let Some(denied) = require_same_site(&headers) {
        return denied;
    }
    // Finish the password change even if the browser disconnects.
    let task = tokio::spawn(async move {
        let _lock = sso.lock(&authorized.identity).await;
        let Some(vault) = vault.read().await.clone() else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        match sso.directory.take_over(&authorized.identity, &vault).await {
            Ok(()) => "The password is now managed for you.".into_response(),
            Err(failure) => failure_response(failure),
        }
    });
    task.await
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// A cross-origin form cannot supply this header.
fn require_same_site(headers: &HeaderMap) -> Option<Response> {
    headers
        .get("x-rustguac-launch")
        .is_none_or(|value| value != "1")
        .then(|| {
            (
                StatusCode::FORBIDDEN,
                "Remote Desktop must be opened from this site.",
            )
                .into_response()
        })
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
        let targets = Targets::parse(TWO_TARGETS, true).unwrap();
        let first = targets
            .for_request(&request_for("RDP-1.example.com:443"))
            .unwrap();
        let second = targets
            .for_request(&request_for("rdp-2.example.com"))
            .unwrap();
        assert_eq!(first.host, "windows-1.local");
        assert_eq!(second.host, "10.0.0.12");
        assert_eq!(first.audience.as_deref(), Some("aud-1"));
        assert_eq!(second.audience.as_deref(), Some("aud-2"));
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
            true,
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
        assert!(Targets::parse(&duplicate, true).is_err());
        assert!(Targets::parse(&invalid_target, true).is_err());
    }

    #[test]
    fn session_ownership_is_bound_to_the_public_hostname() {
        let targets = Targets::parse(TWO_TARGETS, true).unwrap();
        let identity = Identity::new("user@example.com".into(), "test:alice".into()).unwrap();
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
    fn admin_targets_are_hidden_from_other_users() {
        let targets = Targets::parse(
            r#"[
                {"public_host":"autordp.example.com","connect_to":"app","target_host":"app-1","access_aud":"aud"},
                {"public_host":"autordp.example.com","connect_to":"dc","target_host":"dc-1","access_aud":"aud","admin":true}
            ]"#,
            true,
        )
        .unwrap();
        assert!(targets.has_admin_target());
        let menu = targets.menu(&request_for("autordp.example.com")).unwrap();
        let mut identity = Identity::new("user@example.com".into(), "test:alice".into()).unwrap();
        let visible = |identity: &Identity| menu.0.iter().filter(|t| t.allows(identity)).count();
        assert_eq!(visible(&identity), 1);
        identity.admin = true;
        assert_eq!(visible(&identity), 2);
    }
}
