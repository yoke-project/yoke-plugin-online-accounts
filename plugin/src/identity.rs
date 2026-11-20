//! The identity providers: what each one's endpoints are, how a sign-in goes with it, and how a token is
//! renewed. Every request is a form posted to an endpoint and answered with JSON, behind [`Http`], so that a
//! test can answer in the provider's place.
//!
//! - **Microsoft** signs in by device code: the person reads a code and opens a page on any device.
//! - **Google** signs in by authorization code with PKCE and a loopback redirect: the person opens a page in
//!   a browser on this machine, which comes back to a port the Plugin listens on, on `127.0.0.1` alone.
//!   Google gives no calendar scope by device code.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A form posted to an endpoint, answered with a status and a JSON body.
#[async_trait]
pub trait Http: Send + Sync {
    async fn post_form(&self, url: &str, form: &[(&str, String)]) -> Result<(u16, Value), String>;
}

/// The network, over TLS.
pub struct Network(reqwest::Client);

impl Network {
    pub fn new() -> Network {
        Network(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("an HTTP client is built"),
        )
    }
}

impl Default for Network {
    fn default() -> Self {
        Network::new()
    }
}

#[async_trait]
impl Http for Network {
    async fn post_form(&self, url: &str, form: &[(&str, String)]) -> Result<(u16, Value), String> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form.iter().map(|(k, v)| (*k, v.as_str())))
            .finish();
        let response = self
            .0
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| format!("{url} cannot be reached: {e}"))?;
        let status = response.status().as_u16();
        let bytes = response
            .bytes()
            .await
            .map_err(|e| format!("{url} answered nothing whole: {e}"))?;
        let value = serde_json::from_slice(&bytes)
            .map_err(|_| format!("{url} answered {status} with no JSON"))?;
        Ok((status, value))
    }
}

/// How a provider signs a person in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// A code the person enters on a page, on any device.
    Device,
    /// A page opened in a browser on this machine, which redirects to a loopback port.
    Browser,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Device => "device_code",
            Method::Browser => "browser",
        }
    }
}

/// A provider's endpoints, and the scopes every sign-in asks for besides the ones asked.
#[derive(Debug, Clone)]
pub struct Provider {
    pub name: String,
    pub method: Method,
    pub device_url: String,
    pub authorize_url: String,
    pub token_url: String,
    /// Asked at every sign-in: who the person is, and a token that renews.
    pub always: Vec<String>,
    /// Added to the page's address, for a token that renews.
    pub authorize_extra: Vec<(String, String)>,
}

pub fn microsoft(tenant: &str) -> Provider {
    let base = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0");
    Provider {
        name: "microsoft".into(),
        method: Method::Device,
        device_url: format!("{base}/devicecode"),
        authorize_url: format!("{base}/authorize"),
        token_url: format!("{base}/token"),
        always: vec![
            "openid".into(),
            "profile".into(),
            "email".into(),
            "offline_access".into(),
        ],
        authorize_extra: vec![],
    }
}

pub fn google() -> Provider {
    Provider {
        name: "google".into(),
        method: Method::Browser,
        device_url: String::new(),
        authorize_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
        token_url: "https://oauth2.googleapis.com/token".into(),
        always: vec!["openid".into(), "email".into()],
        authorize_extra: vec![
            ("access_type".into(), "offline".into()),
            ("prompt".into(), "consent".into()),
        ],
    }
}

/// The client a deployment registered with a provider: its identifier, and for Google the secret a desktop
/// client is issued, which a desktop client cannot keep secret and the provider still asks for.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// The deployment's clients, by provider: the secret `clients`, as JSON.
pub fn clients(text: &str) -> Result<BTreeMap<String, Client>, String> {
    serde_json::from_str(text)
        .map_err(|e| format!("the clients are not what this Plugin reads: {e}"))
}

/// What a token endpoint gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tokens {
    pub access_token: String,
    pub expires_at: SystemTime,
    /// Absent where a renewal kept the refresh token it was given.
    pub refresh_token: Option<String>,
    /// Absent where the provider did not say.
    pub scopes: Option<Vec<String>>,
    /// Who signed in, from the identity token where one came.
    pub username: Option<String>,
}

/// Why a token endpoint said no.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The person has not finished yet.
    Pending,
    /// Asked too often: wait longer.
    SlowDown,
    /// The grant is no longer good: the person must sign in again.
    Grant(String),
    /// Anything else, with what the provider or the network said.
    Other(String),
}

fn tokens(v: &Value, now: SystemTime) -> Result<Tokens, Refused> {
    let access_token = v["access_token"]
        .as_str()
        .ok_or_else(|| Refused::Other("no access token was given".into()))?;
    let expires_in = v["expires_in"]
        .as_u64()
        .or_else(|| v["expires_in"].as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(3600);
    Ok(Tokens {
        access_token: access_token.to_string(),
        expires_at: now + Duration::from_secs(expires_in),
        refresh_token: v["refresh_token"].as_str().map(str::to_string),
        scopes: v["scope"]
            .as_str()
            .map(|s| s.split_whitespace().map(str::to_string).collect()),
        username: v["id_token"].as_str().and_then(username),
    })
}

fn refused(status: u16, v: &Value) -> Refused {
    let error = v["error"].as_str().unwrap_or_default();
    let said = v["error_description"].as_str().unwrap_or(error);
    match error {
        "authorization_pending" => Refused::Pending,
        "slow_down" => Refused::SlowDown,
        "invalid_grant" | "expired_token" | "access_denied" | "interaction_required" => {
            Refused::Grant(said.to_string())
        }
        "" => Refused::Other(format!("the provider answered {status}")),
        _ => Refused::Other(format!("{error}: {said}")),
    }
}

async fn token_request(
    http: &dyn Http,
    p: &Provider,
    form: &[(&str, String)],
) -> Result<Tokens, Refused> {
    let now = SystemTime::now();
    let (status, v) = http
        .post_form(&p.token_url, form)
        .await
        .map_err(Refused::Other)?;
    if (200..300).contains(&status) && v.get("access_token").is_some() {
        tokens(&v, now)
    } else {
        Err(refused(status, &v))
    }
}

/// Who signed in, read from an identity token the token endpoint handed over TLS: its claims, not its
/// signature, which the channel it came on already vouches for.
pub fn username(id_token: &str) -> Option<String> {
    let claims = id_token.split('.').nth(1)?;
    let claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims.trim_end_matches('=')).ok()?).ok()?;
    ["preferred_username", "email", "upn", "sub"]
        .iter()
        .find_map(|k| {
            claims[*k]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
}

fn client_form<'a>(c: &Client, mut form: Vec<(&'a str, String)>) -> Vec<(&'a str, String)> {
    form.push(("client_id", c.client_id.clone()));
    if let Some(secret) = &c.client_secret {
        form.push(("client_secret", secret.clone()));
    }
    form
}

/// Renews an access token with a refresh token.
pub async fn renew(
    http: &dyn Http,
    p: &Provider,
    c: &Client,
    refresh_token: &str,
) -> Result<Tokens, Refused> {
    let form = client_form(
        c,
        vec![
            ("grant_type", "refresh_token".into()),
            ("refresh_token", refresh_token.into()),
        ],
    );
    token_request(http, p, &form).await
}

/// A device sign-in started: what the person is shown, and what the Plugin polls with.
#[derive(Debug, Clone)]
pub struct DeviceStarted {
    pub device_code: String,
    pub user_code: String,
    pub url: String,
    pub expires_at: SystemTime,
    pub interval: Duration,
}

pub async fn device_start(
    http: &dyn Http,
    p: &Provider,
    c: &Client,
    scopes: &[String],
) -> Result<DeviceStarted, String> {
    let (status, v) = http
        .post_form(
            &p.device_url,
            &[
                ("client_id", c.client_id.clone()),
                ("scope", scopes.join(" ")),
            ],
        )
        .await?;
    let text = |k: &str| v[k].as_str().map(str::to_string);
    match (
        text("device_code"),
        text("user_code"),
        text("verification_uri").or_else(|| text("verification_url")),
    ) {
        (Some(device_code), Some(user_code), Some(url)) if (200..300).contains(&status) => {
            Ok(DeviceStarted {
                device_code,
                user_code,
                url,
                expires_at: SystemTime::now()
                    + Duration::from_secs(v["expires_in"].as_u64().unwrap_or(900)),
                interval: Duration::from_secs(v["interval"].as_u64().unwrap_or(5).max(1)),
            })
        }
        _ => Err(match refused(status, &v) {
            Refused::Grant(m) | Refused::Other(m) => m,
            _ => format!("the provider answered {status}"),
        }),
    }
}

/// Polls until the person has finished, the code expired or the provider refused; `wait` is how long to
/// wait between two polls, a test's being shorter.
pub async fn device_finish(
    http: &dyn Http,
    p: &Provider,
    c: &Client,
    started: &DeviceStarted,
    wait: impl Fn(Duration) -> Duration,
) -> Result<Tokens, String> {
    let mut interval = started.interval;
    loop {
        if SystemTime::now() >= started.expires_at {
            return Err("the code expired before the sign-in was finished".into());
        }
        tokio::time::sleep(wait(interval)).await;
        let form = client_form(
            c,
            vec![
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:device_code".into(),
                ),
                ("device_code", started.device_code.clone()),
            ],
        );
        match token_request(http, p, &form).await {
            Ok(t) => return Ok(t),
            Err(Refused::Pending) => {}
            Err(Refused::SlowDown) => interval += Duration::from_secs(5),
            Err(Refused::Grant(m) | Refused::Other(m)) => return Err(m),
        }
    }
}

fn random(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    getrandom::getrandom(&mut b).expect("the host's random source answers");
    URL_SAFE_NO_PAD.encode(b)
}

/// A browser sign-in started: the page to open, and the loopback port it comes back to.
pub struct BrowserStarted {
    pub url: String,
    pub expires_at: SystemTime,
    listener: TcpListener,
    redirect_uri: String,
    verifier: String,
    state: String,
}

pub async fn browser_start(
    p: &Provider,
    c: &Client,
    scopes: &[String],
    within: Duration,
) -> Result<BrowserStarted, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("no loopback port can be listened on: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}");
    let verifier = random(48);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random(16);
    let mut params: Vec<(String, String)> = vec![
        ("response_type".into(), "code".into()),
        ("client_id".into(), c.client_id.clone()),
        ("redirect_uri".into(), redirect_uri.clone()),
        ("scope".into(), scopes.join(" ")),
        ("code_challenge".into(), challenge),
        ("code_challenge_method".into(), "S256".into()),
        ("state".into(), state.clone()),
    ];
    params.extend(p.authorize_extra.iter().cloned());
    let url = url::Url::parse_with_params(&p.authorize_url, &params)
        .map_err(|e| e.to_string())?
        .to_string();
    Ok(BrowserStarted {
        url,
        expires_at: SystemTime::now() + within,
        listener,
        redirect_uri,
        verifier,
        state,
    })
}

const CLOSE_ME: &str = "<!doctype html><meta charset=utf-8><title>Signed in</title><p>The sign-in came back. This window can be closed.";
const NOT_SIGNED: &str = "<!doctype html><meta charset=utf-8><title>Not signed in</title><p>The sign-in did not come back as expected.";

/// Waits for the browser to come back with a code, then exchanges it.
pub async fn browser_finish(
    http: &dyn Http,
    p: &Provider,
    c: &Client,
    started: BrowserStarted,
) -> Result<Tokens, String> {
    let left = started
        .expires_at
        .duration_since(SystemTime::now())
        .unwrap_or_default();
    let code = tokio::time::timeout(left, async {
        loop {
            let (mut conn, _) = started.listener.accept().await.map_err(|e| e.to_string())?;
            let mut buf = vec![0u8; 8192];
            let n = conn.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let target = head.split_whitespace().nth(1).unwrap_or("/").to_string();
            let Ok(u) = url::Url::parse(&format!("http://127.0.0.1{target}")) else { continue };
            let query: BTreeMap<String, String> = u.query_pairs().into_owned().collect();
            if query.get("state") != Some(&started.state) {
                // A request that is not this sign-in's coming back: a favicon, or a stranger.
                let _ = conn.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
                continue;
            }
            let (page, result) = match (query.get("code"), query.get("error")) {
                (Some(code), _) => (CLOSE_ME, Ok(code.clone())),
                (None, Some(error)) => (NOT_SIGNED, Err(format!("the provider said {error}"))),
                _ => (NOT_SIGNED, Err("the browser came back with no code".to_string())),
            };
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{page}",
                page.len()
            );
            let _ = conn.write_all(reply.as_bytes()).await;
            return result;
        }
    })
    .await
    .map_err(|_| "the browser did not come back before the sign-in expired".to_string())??;
    let form = client_form(
        c,
        vec![
            ("grant_type", "authorization_code".into()),
            ("code", code),
            ("redirect_uri", started.redirect_uri.clone()),
            ("code_verifier", started.verifier.clone()),
        ],
    );
    token_request(http, p, &form).await.map_err(|r| match r {
        Refused::Grant(m) | Refused::Other(m) => m,
        Refused::Pending | Refused::SlowDown => "the provider did not exchange the code".into(),
    })
}
