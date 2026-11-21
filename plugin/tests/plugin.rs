//! The Plugin against a provider that answers as it is told and a Session that records what it is given.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedReceiver;

use online_accounts::accounts::{Account, Give, Tokens};
use online_accounts::identity::{self, Client, Http};
use online_accounts::plugin::*;

type Answer = Box<dyn Fn(&str, &BTreeMap<String, String>) -> (u16, Value) + Send + Sync>;

/// A provider: what it was sent, and an answer for each request.
struct Provider {
    sent: Mutex<Vec<(String, BTreeMap<String, String>)>>,
    answer: Answer,
}

#[async_trait]
impl Http for Provider {
    async fn post_form(&self, url: &str, form: &[(&str, String)]) -> Result<(u16, Value), String> {
        let form: BTreeMap<String, String> = form
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        self.sent
            .lock()
            .unwrap()
            .push((url.to_string(), form.clone()));
        Ok((self.answer)(url, &form))
    }
}

impl Provider {
    fn sent(&self) -> Vec<(String, BTreeMap<String, String>)> {
        self.sent.lock().unwrap().clone()
    }
    fn grants(&self, grant: &str) -> usize {
        self.sent()
            .iter()
            .filter(|(_, f)| f.get("grant_type").map(String::as_str) == Some(grant))
            .count()
    }
}

fn id_token(username: &str) -> String {
    let claims =
        URL_SAFE_NO_PAD.encode(json!({ "preferred_username": username, "sub": "x" }).to_string());
    format!("e30.{claims}.sig")
}

fn account(id: &str, refresh: &str) -> Account {
    let (provider, username) = id.split_once(':').unwrap();
    Account {
        id: id.into(),
        provider: provider.into(),
        username: username.into(),
        scopes: vec!["openid".into(), "Calendars.Read".into()],
        refresh_token: refresh.into(),
    }
}

struct Bench {
    online: Arc<Online>,
    provider: Arc<Provider>,
    happened: UnboundedReceiver<Happened>,
    tokens: PathBuf,
    _dir: TempDir,
}

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ =
            std::fs::set_permissions(&self.0, std::os::unix::fs::PermissionsExt::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp() -> TempDir {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "oa-{}",
        URL_SAFE_NO_PAD.encode(b).replace('-', "x")
    ));
    std::fs::create_dir_all(dir.join("tokens")).unwrap();
    TempDir(dir)
}

fn bench(held: &str, give: &[&str], answer: Answer) -> Bench {
    let dir = temp();
    let tokens = dir.0.join("tokens/value");
    std::fs::write(&tokens, held).unwrap();
    let provider = Arc::new(Provider {
        sent: Mutex::new(vec![]),
        answer,
    });
    let mut g = Give::default();
    for rule in give {
        g.add(rule).unwrap();
    }
    let clients = BTreeMap::from([
        (
            "microsoft".to_string(),
            Client {
                client_id: "ms-client".into(),
                client_secret: None,
            },
        ),
        (
            "google".to_string(),
            Client {
                client_id: "g-client".into(),
                client_secret: Some("g-secret".into()),
            },
        ),
    ]);
    let (tx, happened) = tokio::sync::mpsc::unbounded_channel();
    let parts = Parts {
        http: provider.clone(),
        providers: vec![identity::microsoft("common"), identity::google()],
        clients,
        tokens: Tokens::at(&tokens),
        give: g,
        renew_before: Duration::from_secs(300),
        login_within: Duration::from_secs(30),
        poll_wait: |_| Duration::from_millis(10),
    };
    let (online, _) = Online::new(parts, tx);
    Bench {
        online,
        provider,
        happened,
        tokens,
        _dir: dir,
    }
}

fn held(accounts: &[Account]) -> String {
    json!({ "schema": 1, "accounts": accounts }).to_string()
}

fn renewed(rotate: Option<&str>) -> Answer {
    let rotate = rotate.map(str::to_string);
    Box::new(
        move |_, form| match form.get("grant_type").map(String::as_str) {
            Some("refresh_token") => {
                let mut v = json!({ "access_token": format!("at-{}", form["refresh_token"]), "expires_in": 3600 });
                if let Some(r) = &rotate {
                    v["refresh_token"] = json!(r);
                }
                (200, v)
            }
            _ => (400, json!({ "error": "unsupported_grant_type" })),
        },
    )
}

fn json_of(bytes: Vec<u8>) -> Value {
    serde_json::from_slice(&bytes).unwrap()
}

async fn occurrence(h: &mut UnboundedReceiver<Happened>, want: &str) -> Value {
    let found = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(x) = h.recv().await {
            if let Happened::Occurred {
                occurrence, detail, ..
            } = x
            {
                if occurrence == want {
                    return detail;
                }
            }
        }
        Value::Null
    })
    .await;
    found.unwrap_or_else(|_| panic!("no {want} was reported"))
}

#[test]
fn the_manifest_kept_is_the_declaration_and_rewrites_the_secret_tokens() {
    let kept = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/com.yoke.online-accounts.yaml"
    ))
    .unwrap();
    assert_eq!(declaration().manifest(), kept);
    let d = declaration();
    assert_eq!(d.needs, vec!["secret:clients", "secret:tokens"]);
    assert_eq!(d.rewrites, vec!["tokens"]);
}

#[test]
fn the_arguments_name_both_secrets_and_who_is_given_what() {
    let args = |a: &[&str]| Settings::parse(a.iter().map(|s| s.to_string()));
    assert!(args(&["--tokens", "/t"]).is_err());
    let s = args(&[
        "--clients",
        "/c",
        "--tokens",
        "/t",
        "--give",
        "unit:calendar=google:*",
        "--tenant",
        "consumers",
    ])
    .unwrap();
    assert_eq!(
        (s.clients, s.tokens, s.tenant.as_str()),
        (PathBuf::from("/c"), PathBuf::from("/t"), "consumers")
    );
    assert!(s
        .give
        .may("unit:calendar", &account("google:ada@example.org", "r")));
    assert!(!s
        .give
        .may("unit:calendar", &account("microsoft:ada@example.org", "r")));
    assert!(!s
        .give
        .may("unit:mail", &account("google:ada@example.org", "r")));
    assert!(Give::default().may("unit:anyone", &account("google:ada@example.org", "r")));
    assert!(args(&["--clients", "/c", "--tokens", "/t", "--give", "nobody"]).is_err());
}

#[tokio::test]
async fn what_is_given_is_scoped_by_who_asks() {
    let b = bench(
        &held(&[
            account("google:ada@example.org", "rg"),
            account("microsoft:ada@example.org", "rm"),
        ]),
        &["unit:calendar=google:*", "operator:ada=*"],
        renewed(None),
    );
    let listed = |v: Value| {
        v["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    let calendar = json_of(
        b.online
            .answer("unit:calendar", ACCOUNTS, b"{}")
            .await
            .unwrap(),
    );
    assert_eq!(listed(calendar), vec!["google:ada@example.org"]);
    let operator = json_of(
        b.online
            .answer("operator:ada", ACCOUNTS, b"")
            .await
            .unwrap(),
    );
    assert_eq!(listed(operator).len(), 2);
    assert!(listed(json_of(
        b.online
            .answer("channel:panel", ACCOUNTS, b"")
            .await
            .unwrap()
    ))
    .is_empty());
    let refused = b
        .online
        .answer(
            "unit:calendar",
            TOKEN,
            br#"{"account":"microsoft:ada@example.org"}"#,
        )
        .await
        .unwrap_err();
    assert_eq!(code(&refused), "not_found");
    let token = json_of(
        b.online
            .answer(
                "unit:calendar",
                TOKEN,
                br#"{"account":"google:ada@example.org"}"#,
            )
            .await
            .unwrap(),
    );
    assert_eq!(token["access_token"], "at-rg");
    // Nothing of a token travels in the list.
    assert!(!String::from_utf8(
        b.online
            .answer("operator:ada", ACCOUNTS, b"")
            .await
            .unwrap()
    )
    .unwrap()
    .contains("\"rg\""));
}

#[tokio::test]
async fn a_token_is_renewed_once_and_a_rotated_refresh_token_is_rewritten_in_place() {
    let b = bench(
        &held(&[account("microsoft:ada@example.org", "r1")]),
        &[],
        renewed(Some("r2")),
    );
    let ask = || {
        b.online.answer(
            "unit:calendar",
            TOKEN,
            br#"{"account":"microsoft:ada@example.org"}"#,
        )
    };
    let first = json_of(ask().await.unwrap());
    assert_eq!(first["access_token"], "at-r1");
    assert_eq!(first["token_type"], "Bearer");
    let second = json_of(ask().await.unwrap());
    assert_eq!(
        second["access_token"], "at-r1",
        "a token still good is answered again"
    );
    assert_eq!(b.provider.grants("refresh_token"), 1);
    let rested: Value = serde_json::from_str(&std::fs::read_to_string(&b.tokens).unwrap()).unwrap();
    assert_eq!(rested["accounts"][0]["refresh_token"], "r2");
    let dir = b.tokens.parent().unwrap();
    assert_eq!(
        std::fs::read_dir(dir).unwrap().count(),
        1,
        "nothing but the value is left beside it"
    );
}

#[tokio::test]
async fn a_scope_the_account_was_not_granted_is_refused() {
    let b = bench(
        &held(&[account("microsoft:ada@example.org", "r1")]),
        &[],
        renewed(None),
    );
    let e = b
        .online
        .answer(
            "unit:mail",
            TOKEN,
            br#"{"account":"microsoft:ada@example.org","scopes":["Mail.Read"]}"#,
        )
        .await
        .unwrap_err();
    assert_eq!(code(&e), "scope.missing");
    assert_eq!(b.provider.grants("refresh_token"), 0);
}

#[tokio::test]
async fn a_grant_no_longer_honoured_is_to_sign_in_again_and_said_once() {
    let mut b = bench(
        &held(&[account("google:ada@example.org", "r1")]),
        &[],
        Box::new(|_, _| {
            (
                400,
                json!({ "error": "invalid_grant", "error_description": "Token has been expired or revoked." }),
            )
        }),
    );
    let ask = || {
        b.online.answer(
            "unit:calendar",
            TOKEN,
            br#"{"account":"google:ada@example.org"}"#,
        )
    };
    assert_eq!(code(&ask().await.unwrap_err()), "sign_in_again");
    let detail = occurrence(&mut b.happened, SIGN_IN_AGAIN).await;
    assert_eq!(detail["account"], "google:ada@example.org");
    assert_eq!(code(&ask().await.unwrap_err()), "sign_in_again");
    assert_eq!(
        b.provider.grants("refresh_token"),
        1,
        "a refused grant is not tried again"
    );
    let record = b.online.record().await;
    assert_eq!(record["accounts"][0]["state"], "sign_in_again");
}

#[tokio::test]
async fn a_device_sign_in_shows_its_code_then_keeps_the_account() {
    let polls = Arc::new(Mutex::new(0));
    let counted = polls.clone();
    let mut b = bench(
        "",
        &[],
        Box::new(move |url, form| {
            if url.ends_with("/devicecode") {
                return (
                    200,
                    json!({ "device_code": "dc", "user_code": "ABCD-EFGH", "verification_uri": "https://microsoft.com/devicelogin", "expires_in": 900, "interval": 1 }),
                );
            }
            assert_eq!(form["device_code"], "dc");
            let mut n = counted.lock().unwrap();
            *n += 1;
            if *n < 2 {
                (400, json!({ "error": "authorization_pending" }))
            } else {
                (
                    200,
                    json!({ "access_token": "secret-access", "expires_in": 3600, "refresh_token": "rt", "scope": "openid offline_access Calendars.Read", "id_token": id_token("ada@example.org") }),
                )
            }
        }),
    );
    let line = b
        .online
        .act(
            LOGIN,
            br#"{"provider":"microsoft","scopes":["Calendars.Read"]}"#,
        )
        .await
        .unwrap();
    assert!(
        line.contains("ABCD-EFGH") && line.contains("https://microsoft.com/devicelogin"),
        "{line}"
    );
    let asked = &b.provider.sent()[0].1;
    assert!(asked["scope"].contains("offline_access") && asked["scope"].contains("Calendars.Read"));
    let shown = b.online.record().await;
    assert_eq!(shown["logins"][0]["user_code"], "ABCD-EFGH");
    assert_eq!(shown["logins"][0]["method"], "device_code");
    let detail = occurrence(&mut b.happened, SIGNED_IN).await;
    assert_eq!(detail["account"], "microsoft:ada@example.org");
    assert_eq!(detail["withheld"], json!([]));
    let after = b.online.record().await;
    assert!(after["logins"].as_array().unwrap().is_empty());
    assert_eq!(after["accounts"][0]["state"], "valid");
    assert!(
        !after.to_string().contains("\"rt\"") && !after.to_string().contains("secret-access"),
        "the stream carries no token"
    );
    let rested: Value = serde_json::from_str(&std::fs::read_to_string(&b.tokens).unwrap()).unwrap();
    assert_eq!(rested["accounts"][0]["refresh_token"], "rt");
    assert_eq!(
        rested["accounts"][0]["scopes"],
        json!(["openid", "offline_access", "Calendars.Read"])
    );
}

#[tokio::test]
async fn a_sign_in_granted_less_than_asked_keeps_what_was_granted_and_says_what_was_not() {
    let mut b = bench(
        "",
        &[],
        Box::new(|url, _| {
            if url.ends_with("/devicecode") {
                return (
                    200,
                    json!({ "device_code": "dc", "user_code": "ABCD-EFGH", "verification_uri": "https://microsoft.com/devicelogin", "expires_in": 900, "interval": 1 }),
                );
            }
            (
                200,
                json!({ "access_token": "at", "expires_in": 3600, "refresh_token": "rt", "scope": "openid offline_access", "id_token": id_token("ada@example.org") }),
            )
        }),
    );
    b.online
        .act(
            LOGIN,
            br#"{"provider":"microsoft","scopes":["Calendars.Read"]}"#,
        )
        .await
        .unwrap();
    let detail = occurrence(&mut b.happened, SIGNED_IN).await;
    assert_eq!(detail["withheld"], json!(["Calendars.Read"]));
    let line = detail["line"].as_str().unwrap();
    assert!(line.contains("was not granted Calendars.Read"), "{line}");
    let after = b.online.record().await;
    assert_eq!(
        after["accounts"][0]["scopes"],
        json!(["openid", "offline_access"])
    );
}

#[tokio::test]
async fn a_browser_sign_in_comes_back_to_the_loopback_with_its_state_and_proves_its_verifier() {
    let mut b = bench(
        "",
        &[],
        Box::new(|_, form| {
            if form.get("grant_type").map(String::as_str) == Some("authorization_code") {
                (
                    200,
                    json!({ "access_token": "at", "expires_in": 3600, "refresh_token": "rt", "id_token": id_token("ada@example.org") }),
                )
            } else {
                (400, json!({ "error": "unsupported_grant_type" }))
            }
        }),
    );
    b.online.act(LOGIN, br#"{"provider":"google","scopes":["https://www.googleapis.com/auth/calendar.readonly"]}"#).await.unwrap();
    let record = b.online.record().await;
    let page = url::Url::parse(record["logins"][0]["url"].as_str().unwrap()).unwrap();
    let q: BTreeMap<String, String> = page.query_pairs().into_owned().collect();
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["access_type"], "offline");
    let redirect = url::Url::parse(&q["redirect_uri"]).unwrap();
    assert_eq!(redirect.host_str(), Some("127.0.0.1"));
    let port = redirect.port().unwrap();
    // A stranger first, then the browser.
    for (state, code) in [("wrong", "x"), (q["state"].as_str(), "the-code")] {
        let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        conn.write_all(
            format!("GET /?state={state}&code={code} HTTP/1.1\r\nhost: x\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let mut reply = String::new();
        conn.read_to_string(&mut reply).await.unwrap();
        assert!(
            reply.starts_with(if state == "wrong" {
                "HTTP/1.1 404"
            } else {
                "HTTP/1.1 200"
            }),
            "{reply}"
        );
    }
    let detail = occurrence(&mut b.happened, SIGNED_IN).await;
    assert_eq!(detail["account"], "google:ada@example.org");
    let (_, exchanged) = b
        .provider
        .sent()
        .into_iter()
        .find(|(_, f)| f.get("grant_type").map(String::as_str) == Some("authorization_code"))
        .unwrap();
    assert_eq!(exchanged["code"], "the-code");
    assert_eq!(exchanged["client_secret"], "g-secret");
    let proved = URL_SAFE_NO_PAD.encode(<sha2::Sha256 as sha2::Digest>::digest(
        exchanged["code_verifier"].as_bytes(),
    ));
    assert_eq!(proved, q["code_challenge"]);
}

#[tokio::test]
async fn a_sign_in_that_fails_is_said_and_keeps_nothing() {
    let mut b = bench(
        "",
        &[],
        Box::new(|url, _| {
            if url.ends_with("/devicecode") {
                (
                    200,
                    json!({ "device_code": "dc", "user_code": "C", "verification_uri": "https://x", "expires_in": 900, "interval": 1 }),
                )
            } else {
                (
                    400,
                    json!({ "error": "access_denied", "error_description": "the person declined" }),
                )
            }
        }),
    );
    b.online
        .act(LOGIN, br#"{"provider":"microsoft"}"#)
        .await
        .unwrap();
    let detail = occurrence(&mut b.happened, LOGIN_FAILED).await;
    assert!(detail["line"].as_str().unwrap().contains("declined"));
    assert!(b.online.record().await["accounts"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(std::fs::read_to_string(&b.tokens).unwrap(), "");
}

#[tokio::test]
async fn a_provider_with_no_client_or_none_known_is_refused_before_anything_is_sent() {
    let b = bench("", &[], renewed(None));
    assert_eq!(
        code(
            &b.online
                .act(LOGIN, br#"{"provider":"yahoo"}"#)
                .await
                .unwrap_err()
        ),
        "not_found"
    );
    assert_eq!(
        code(
            &b.online
                .act(LOGIN, br#"{"provider":"microsoft","extra":1}"#)
                .await
                .unwrap_err()
        ),
        "invalid"
    );
    assert!(b.provider.sent().is_empty());
}

#[tokio::test]
async fn a_logout_forgets_the_account_in_the_secret() {
    let b = bench(
        &held(&[
            account("google:ada@example.org", "rg"),
            account("microsoft:ada@example.org", "rm"),
        ]),
        &[],
        renewed(None),
    );
    b.online
        .act(LOGOUT, br#"{"account":"google:ada@example.org"}"#)
        .await
        .unwrap();
    let rested: Value = serde_json::from_str(&std::fs::read_to_string(&b.tokens).unwrap()).unwrap();
    assert_eq!(rested["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(rested["accounts"][0]["id"], "microsoft:ada@example.org");
    assert_eq!(
        code(
            &b.online
                .act(LOGOUT, br#"{"account":"google:ada@example.org"}"#)
                .await
                .unwrap_err()
        ),
        "not_found"
    );
}

#[tokio::test]
async fn a_secret_this_plugin_did_not_write_is_never_overwritten() {
    let b = bench("not json", &[], renewed(None));
    let e = b
        .online
        .act(LOGIN, br#"{"provider":"microsoft"}"#)
        .await
        .unwrap_err();
    assert_eq!(code(&e), "unavailable");
    assert_eq!(std::fs::read_to_string(&b.tokens).unwrap(), "not json");
}

#[tokio::test]
async fn the_unit_renews_what_runs_out_on_its_own() {
    let b = bench(
        &held(&[account("microsoft:ada@example.org", "r1")]),
        &[],
        renewed(None),
    );
    assert_eq!(b.online.record().await["accounts"][0]["state"], "expiring");
    b.online.renew_due().await;
    assert_eq!(b.online.record().await["accounts"][0]["state"], "valid");
    b.online.renew_due().await;
    assert_eq!(b.provider.grants("refresh_token"), 1);
}
