//! The online-accounts Plugin: accounts held, signed in and renewed, as questions, a stream, commands and
//! occurrences.
//!
//! - **`oauth.token` answers an access token** for an account the asker is given, renewing it first where it
//!   runs out within a minute. The Core says who asked; the unit's arguments say who is given what.
//! - **`oauth.accounts` lists the accounts the asker is given**, each with where it stands.
//! - **`oauth.status` is the whole record at every change**: every account and where it stands, and every
//!   sign-in in progress with the page and the code a person needs — never a token.
//! - **`oauth.login` starts a sign-in and `oauth.logout` forgets an account.** A sign-in finishes on its own
//!   time, after the command is acknowledged: the stream shows it until it ends, and an occurrence says how.
//! - **A refresh token rests in the secret `tokens`**, rewritten by this unit at every change of it.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::mpsc::UnboundedSender;
use yoke_sdk::plugin::{
    Capability, Command, Declaration, Event, Object, Outcome, Question, Severity, Stream, Unit,
};

use crate::accounts::{Account, Book, Give, Live, State, Tokens};
use crate::identity::{self, Client, Http, Method, Provider, Refused};

pub const PLUGIN: &str = "com.yoke.online-accounts";
/// The format every answer, frame and detail states as `schema`.
pub const SCHEMA: u32 = 1;

pub const ACCOUNTS: &str = "oauth.accounts";
pub const TOKEN: &str = "oauth.token";
pub const QUERIES: [&str; 2] = [ACCOUNTS, TOKEN];

pub const STATUS: &str = "oauth.status";
pub const STREAMS: [&str; 1] = [STATUS];

pub const LOGIN: &str = "oauth.login";
pub const LOGOUT: &str = "oauth.logout";
pub const COMMANDS: [&str; 2] = [LOGIN, LOGOUT];

pub const SIGNED_IN: &str = "oauth.signed_in";
pub const SIGN_IN_AGAIN: &str = "oauth.sign_in_again";
pub const LOGIN_FAILED: &str = "oauth.login.failed";
pub const OCCURRENCES: [&str; 3] = [SIGNED_IN, SIGN_IN_AGAIN, LOGIN_FAILED];

/// The secrets the unit needs: the deployment's clients, and the accounts it rewrites itself.
pub const CLIENTS_SECRET: &str = "clients";
pub const TOKENS_SECRET: &str = "tokens";

/// How long before it runs out an access token is renewed by the unit on its own, and how long a sign-in
/// waits for the person, unless the unit's arguments say otherwise.
pub const RENEW_BEFORE_S: u64 = 300;
pub const LOGIN_WITHIN_S: u64 = 600;
/// An access token answered is good for at least this long.
pub const ANSWERED_FOR: Duration = Duration::from_secs(60);

pub fn declaration() -> Declaration {
    let answer = |q: &&str| Capability {
        name: format!("query.{q}.answer"),
        governs: Object::Query(q.to_string()),
    };
    let accept = |c: &&str| Capability {
        name: format!("command.{c}.accept"),
        governs: Object::Command(c.to_string()),
    };
    let publish = |s: &&str| Capability {
        name: format!("stream.{s}.publish"),
        governs: Object::Stream(s.to_string()),
    };
    let report = |o: &&str| Capability {
        name: format!("event.{o}.report"),
        governs: Object::Occurrence(o.to_string()),
    };
    Declaration {
        id: PLUGIN.into(),
        needs: vec![
            format!("secret:{CLIENTS_SECRET}"),
            format!("secret:{TOKENS_SECRET}"),
        ],
        queries: QUERIES.iter().map(|q| q.to_string()).collect(),
        commands: COMMANDS.iter().map(|c| c.to_string()).collect(),
        // The whole record again at every change, so a lost frame is made good by the next.
        streams: vec![Stream {
            id: STATUS.into(),
            tolerates_loss: true,
            tolerates_reorder: false,
            max_frame: 0,
        }],
        occurrences: OCCURRENCES.iter().map(|o| o.to_string()).collect(),
        capabilities: QUERIES
            .iter()
            .map(answer)
            .chain(COMMANDS.iter().map(accept))
            .chain(STREAMS.iter().map(publish))
            .chain(OCCURRENCES.iter().map(report))
            .collect(),
        rewrites: vec![TOKENS_SECRET.into()],
        ..Default::default()
    }
}

/// What the unit's arguments choose: `--clients ${bind.clients} --tokens ${bind.tokens}`, and
/// `--give <asker>=<accounts>` (repeated), `--tenant <tenant>`, `--renew-before-s N`, `--login-within-s N`.
#[derive(Debug, PartialEq, Eq)]
pub struct Settings {
    pub clients: PathBuf,
    pub tokens: PathBuf,
    pub give: Give,
    pub tenant: String,
    pub renew_before: Duration,
    pub login_within: Duration,
}

impl Settings {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Settings, String> {
        let (mut clients, mut tokens) = (None, None);
        let mut s = Settings {
            clients: PathBuf::new(),
            tokens: PathBuf::new(),
            give: Give::default(),
            tenant: "common".into(),
            renew_before: Duration::from_secs(RENEW_BEFORE_S),
            login_within: Duration::from_secs(LOGIN_WITHIN_S),
        };
        let mut it = args.into_iter();
        while let Some(flag) = it.next() {
            let mut value = || it.next().ok_or(format!("{flag} takes a value"));
            match flag.as_str() {
                "--clients" => clients = Some(PathBuf::from(value()?)),
                "--tokens" => tokens = Some(PathBuf::from(value()?)),
                "--give" => s.give.add(&value()?)?,
                "--tenant" => s.tenant = value()?,
                "--renew-before-s" => {
                    s.renew_before = Duration::from_secs(
                        value()?
                            .parse()
                            .map_err(|_| format!("{flag} takes a number"))?,
                    )
                }
                "--login-within-s" => {
                    s.login_within = Duration::from_secs(
                        value()?
                            .parse()
                            .map_err(|_| format!("{flag} takes a number"))?,
                    )
                }
                other => return Err(format!("unknown argument {other}")),
            }
        }
        s.clients = clients.ok_or("--clients names the secret clients: ${bind.clients}")?;
        s.tokens = tokens.ok_or("--tokens names the secret tokens: ${bind.tokens}")?;
        Ok(s)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(String),
    NotFound(String),
    SignInAgain(String),
    ScopeMissing(String),
    Unconfigured(String),
    Unavailable(String),
}

pub fn code(e: &Error) -> &'static str {
    match e {
        Error::Invalid(_) => "invalid",
        Error::NotFound(_) => "not_found",
        Error::SignInAgain(_) => "sign_in_again",
        Error::ScopeMissing(_) => "scope.missing",
        Error::Unconfigured(_) => "provider.unconfigured",
        Error::Unavailable(_) => "unavailable",
    }
}

pub fn message(e: &Error) -> String {
    match e {
        Error::Invalid(m)
        | Error::NotFound(m)
        | Error::SignInAgain(m)
        | Error::ScopeMissing(m)
        | Error::Unconfigured(m)
        | Error::Unavailable(m) => m.clone(),
    }
}

fn input<T: DeserializeOwned>(what: &str, payload: &[u8]) -> Result<T, Error> {
    let payload = if payload.iter().all(u8::is_ascii_whitespace) {
        b"{}".as_slice()
    } else {
        payload
    };
    serde_json::from_slice(payload).map_err(|e| {
        let kind = match e.classify() {
            serde_json::error::Category::Data => "a field is missing, unknown or of the wrong type",
            _ => "it is not JSON",
        };
        Error::Invalid(format!(
            "the payload is not what {what} takes: {kind}, at line {} column {}",
            e.line(),
            e.column()
        ))
    })
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NoInput {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenInput {
    pub account: String,
    /// The scopes the token must carry; the account's own where none are named.
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginInput {
    pub provider: String,
    /// The scopes asked of the person, besides who they are and a token that renews.
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountInput {
    pub account: String,
}

fn ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

/// What the Plugin does on the Session, behind a trait so that a test can stand in for the Core.
pub trait Acts {
    fn answer(
        &self,
        q: &Question,
        payload: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), yoke_sdk::base::Error>>;
    fn fail(
        &self,
        q: &Question,
        code: &str,
        message: &str,
    ) -> impl std::future::Future<Output = Result<(), yoke_sdk::base::Error>>;
    fn ack(
        &self,
        c: &Command,
        outcome: Outcome,
        line: &str,
    ) -> impl std::future::Future<Output = Result<(), yoke_sdk::base::Error>>;
    /// An occurrence, its facts as JSON in its detail.
    fn report(
        &self,
        occurrence: &str,
        severity: u8,
        line: &str,
        detail: Value,
    ) -> impl std::future::Future<Output = Result<(), yoke_sdk::base::Error>>;
    fn emit(
        &self,
        stream: &str,
        payload: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), yoke_sdk::base::Error>>;
}

impl Acts for Unit {
    async fn answer(&self, q: &Question, payload: Vec<u8>) -> Result<(), yoke_sdk::base::Error> {
        Unit::answer(self, q, payload).await
    }
    async fn fail(
        &self,
        q: &Question,
        code: &str,
        message: &str,
    ) -> Result<(), yoke_sdk::base::Error> {
        Unit::fail(self, &q.id, code, message).await
    }
    async fn ack(
        &self,
        c: &Command,
        outcome: Outcome,
        line: &str,
    ) -> Result<(), yoke_sdk::base::Error> {
        Unit::ack(self, c, outcome, line).await
    }
    async fn report(
        &self,
        occurrence: &str,
        severity: u8,
        line: &str,
        detail: Value,
    ) -> Result<(), yoke_sdk::base::Error> {
        Unit::report(
            self,
            occurrence,
            Some(Severity::of(severity)),
            line,
            detail.to_string().into_bytes(),
        )
        .await
    }
    async fn emit(&self, stream: &str, payload: Vec<u8>) -> Result<(), yoke_sdk::base::Error> {
        Unit::emit(self, stream, payload).await
    }
}

/// What happened apart from a question or a command, for the Session to carry: the record changed, or an
/// occurrence to report.
#[derive(Debug, Clone, PartialEq)]
pub enum Happened {
    Changed,
    Occurred {
        occurrence: &'static str,
        severity: u8,
        line: String,
        detail: Value,
    },
}

/// A sign-in in progress, as the stream shows it.
#[derive(Debug, Clone)]
struct Login {
    provider: String,
    method: Method,
    url: String,
    user_code: Option<String>,
    expires_at: SystemTime,
}

/// What the Plugin is built from, apart from the Session.
pub struct Parts {
    pub http: Arc<dyn Http>,
    pub providers: Vec<Provider>,
    pub clients: BTreeMap<String, Client>,
    pub tokens: Tokens,
    pub give: Give,
    pub renew_before: Duration,
    pub login_within: Duration,
    /// How long a device sign-in waits between two polls, for an interval the provider set.
    pub poll_wait: fn(Duration) -> Duration,
}

pub struct Online {
    http: Arc<dyn Http>,
    providers: BTreeMap<String, Provider>,
    clients: BTreeMap<String, Client>,
    tokens: Tokens,
    give: Give,
    margin: Duration,
    login_within: Duration,
    poll_wait: fn(Duration) -> Duration,
    /// Held across a renewal, so that a refresh token is never spent twice.
    book: tokio::sync::Mutex<Book>,
    /// Why the secret tokens may not be written, where it may not: a value this Plugin did not write is not
    /// overwritten.
    unwritable: Mutex<Option<String>>,
    logins: Mutex<BTreeMap<String, Login>>,
    login_count: AtomicU64,
    sequence: AtomicU64,
    emitted: AtomicU64,
    flows: AtomicBool,
    publishing: tokio::sync::Mutex<()>,
    happened: UnboundedSender<Happened>,
}

impl Online {
    /// The Plugin from its parts, with the accounts the secret tokens holds; the line says how that went.
    pub fn new(
        parts: Parts,
        happened: UnboundedSender<Happened>,
    ) -> (Arc<Online>, Result<usize, String>) {
        let (accounts, read) = match parts.tokens.read() {
            Ok(a) => {
                let n = a.len();
                (a, Ok(n))
            }
            Err(why) => (vec![], Err(why)),
        };
        let online = Arc::new(Online {
            http: parts.http,
            providers: parts
                .providers
                .into_iter()
                .map(|p| (p.name.clone(), p))
                .collect(),
            clients: parts.clients,
            tokens: parts.tokens,
            give: parts.give,
            margin: parts.renew_before,
            login_within: parts.login_within,
            poll_wait: parts.poll_wait,
            book: tokio::sync::Mutex::new(Book {
                accounts,
                ..Default::default()
            }),
            unwritable: Mutex::new(read.as_ref().err().cloned()),
            logins: Mutex::new(BTreeMap::new()),
            login_count: AtomicU64::new(0),
            sequence: AtomicU64::new(1),
            emitted: AtomicU64::new(0),
            flows: AtomicBool::new(false),
            publishing: tokio::sync::Mutex::new(()),
            happened,
        });
        (online, read)
    }

    fn changed(&self) {
        self.sequence.fetch_add(1, Ordering::Relaxed);
        let _ = self.happened.send(Happened::Changed);
    }

    fn occurred(&self, occurrence: &'static str, severity: u8, line: String, detail: Value) {
        let _ = self.happened.send(Happened::Occurred {
            occurrence,
            severity,
            line,
            detail,
        });
    }

    fn write(&self, book: &Book) -> Result<(), Error> {
        if let Some(why) = self.unwritable.lock().unwrap().clone() {
            return Err(Error::Unavailable(format!("{why}; it is left as it is")));
        }
        self.tokens
            .write(&book.accounts)
            .map_err(Error::Unavailable)
    }

    fn account_json(&self, book: &Book, a: &Account, now: SystemTime) -> Value {
        let state = book.state(&a.id, self.margin, now);
        json!({
            "id": a.id,
            "provider": a.provider,
            "username": a.username,
            "scopes": a.scopes,
            "state": state.as_str(),
            "expires_at": book.live.get(&a.id).map(|l| ms(l.expires_at)),
            "line": book.refused.get(&a.id),
        })
    }

    /// The record the stream carries: every account, and every sign-in in progress. No token.
    pub async fn record(&self) -> Value {
        let now = SystemTime::now();
        let book = self.book.lock().await;
        let logins: Vec<Value> = self
            .logins
            .lock()
            .unwrap()
            .iter()
            .map(|(id, l)| {
                json!({
                    "login": id,
                    "provider": l.provider,
                    "method": l.method.as_str(),
                    "url": l.url,
                    "user_code": l.user_code,
                    "expires_at": ms(l.expires_at),
                })
            })
            .collect();
        json!({
            "schema": SCHEMA,
            "sequence": self.sequence.load(Ordering::Relaxed),
            "at": ms(now),
            "accounts": book.accounts.iter().map(|a| self.account_json(&book, a, now)).collect::<Vec<_>>(),
            "logins": logins,
        })
    }

    /// Emits the record where the stream flows and it changed since it was last emitted.
    pub async fn publish(&self, u: &impl Acts) -> Result<(), yoke_sdk::base::Error> {
        if !self.flows.load(Ordering::Relaxed) {
            return Ok(());
        }
        let _one = self.publishing.lock().await;
        let record = self.record().await;
        let sequence = record["sequence"].as_u64().unwrap_or(0);
        if self.emitted.fetch_max(sequence, Ordering::Relaxed) >= sequence {
            return Ok(());
        }
        u.emit(STATUS, record.to_string().into_bytes()).await
    }

    /// The stream was activated: it is given the present record at once.
    pub async fn activated(
        &self,
        u: &impl Acts,
        stream: &str,
    ) -> Result<(), yoke_sdk::base::Error> {
        if stream != STATUS {
            return Ok(());
        }
        self.flows.store(true, Ordering::Relaxed);
        let _one = self.publishing.lock().await;
        let record = self.record().await;
        self.emitted
            .fetch_max(record["sequence"].as_u64().unwrap_or(0), Ordering::Relaxed);
        u.emit(STATUS, record.to_string().into_bytes()).await
    }

    pub fn stopped(&self, stream: &str) {
        if stream == STATUS {
            self.flows.store(false, Ordering::Relaxed);
        }
    }

    /// Renews one account's access token, the book held. A new refresh token is written at once; a grant the
    /// provider no longer honours marks the account to sign in again.
    async fn renew(&self, book: &mut Book, id: &str) -> Result<Live, Error> {
        let account = book
            .get(id)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("there is no account {id}")))?;
        if let Some(why) = book.refused.get(id) {
            return Err(Error::SignInAgain(format!(
                "{id} must sign in again: {why}"
            )));
        }
        let provider = self.providers.get(&account.provider).ok_or_else(|| {
            Error::Unconfigured(format!(
                "{} is not a provider this Plugin knows",
                account.provider
            ))
        })?;
        let client = self.clients.get(&account.provider).ok_or_else(|| {
            Error::Unconfigured(format!("the clients name no {} client", account.provider))
        })?;
        match identity::renew(self.http.as_ref(), provider, client, &account.refresh_token).await {
            Ok(t) => {
                let live = Live {
                    access_token: t.access_token,
                    expires_at: t.expires_at,
                };
                book.live.insert(id.to_string(), live.clone());
                if let Some(rotated) = t.refresh_token.filter(|r| *r != account.refresh_token) {
                    if let Some(a) = book.accounts.iter_mut().find(|a| a.id == id) {
                        a.refresh_token = rotated;
                    }
                    self.write(book)?;
                }
                self.changed();
                Ok(live)
            }
            Err(Refused::Grant(why)) => {
                book.refused.insert(id.to_string(), why.clone());
                book.live.remove(id);
                self.changed();
                let line = format!("{id} must sign in again");
                self.occurred(SIGN_IN_AGAIN, 40, line.clone(), json!({ "schema": SCHEMA, "line": line, "account": id, "provider": account.provider }));
                Err(Error::SignInAgain(format!(
                    "{id} must sign in again: {why}"
                )))
            }
            Err(Refused::Other(why)) => Err(Error::Unavailable(format!(
                "{id} cannot be renewed now: {why}"
            ))),
            Err(Refused::Pending | Refused::SlowDown) => {
                Err(Error::Unavailable(format!("{id} cannot be renewed now")))
            }
        }
    }

    /// Renews every account whose access token runs out within the margin, or that has none.
    pub async fn renew_due(&self) {
        let mut book = self.book.lock().await;
        let now = SystemTime::now();
        let due: Vec<String> = book
            .accounts
            .iter()
            .filter(|a| book.state(&a.id, self.margin, now) == State::Expiring)
            .map(|a| a.id.clone())
            .collect();
        for id in due {
            let _ = self.renew(&mut book, &id).await;
        }
    }

    /// Answers a question asked by `asker`.
    pub async fn answer(&self, asker: &str, query: &str, payload: &[u8]) -> Result<Vec<u8>, Error> {
        match query {
            ACCOUNTS => {
                let _: NoInput = input(query, payload)?;
                let now = SystemTime::now();
                let book = self.book.lock().await;
                let given: Vec<Value> = book
                    .accounts
                    .iter()
                    .filter(|a| self.give.may(asker, a))
                    .map(|a| self.account_json(&book, a, now))
                    .collect();
                Ok(json!({ "schema": SCHEMA, "accounts": given })
                    .to_string()
                    .into_bytes())
            }
            TOKEN => {
                let i: TokenInput = input(query, payload)?;
                let mut book = self.book.lock().await;
                // An account the asker is not given is one it cannot tell from one that does not exist.
                let account = book
                    .get(&i.account)
                    .filter(|a| self.give.may(asker, a))
                    .cloned()
                    .ok_or_else(|| {
                        Error::NotFound(format!("there is no account {} for {asker}", i.account))
                    })?;
                if let Some(missing) = i.scopes.iter().find(|s| !account.scopes.contains(s)) {
                    return Err(Error::ScopeMissing(format!(
                        "{} was not granted {missing}: sign in again asking for it",
                        account.id
                    )));
                }
                let live = match book.live.get(&account.id) {
                    Some(l)
                        if l.expires_at > SystemTime::now() + ANSWERED_FOR
                            && !book.refused.contains_key(&account.id) =>
                    {
                        l.clone()
                    }
                    _ => self.renew(&mut book, &account.id).await?,
                };
                Ok(json!({
                    "schema": SCHEMA,
                    "account": account.id,
                    "access_token": live.access_token,
                    "token_type": "Bearer",
                    "expires_at": ms(live.expires_at),
                    "scopes": account.scopes,
                })
                .to_string()
                .into_bytes())
            }
            other => Err(Error::Invalid(format!(
                "{other} is not a question of {PLUGIN}"
            ))),
        }
    }

    /// Carries a command out, and returns the line it is acknowledged with. A sign-in goes on after it.
    pub async fn act(self: &Arc<Self>, command: &str, payload: &[u8]) -> Result<String, Error> {
        match command {
            LOGIN => {
                let i: LoginInput = input(command, payload)?;
                let provider = self.providers.get(&i.provider).cloned().ok_or_else(|| {
                    Error::NotFound(format!(
                        "{} is not a provider: {}",
                        i.provider,
                        self.providers
                            .keys()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                })?;
                let client = self
                    .clients
                    .get(&i.provider)
                    .cloned()
                    .ok_or_else(|| Error::Unconfigured(format!("the clients name no {} client: the deployment registers one and supplies it", i.provider)))?;
                if let Some(why) = self.unwritable.lock().unwrap().clone() {
                    return Err(Error::Unavailable(format!("{why}: no sign-in can be kept")));
                }
                let mut scopes = provider.always.clone();
                scopes.extend(
                    i.scopes
                        .iter()
                        .filter(|s| !provider.always.contains(s))
                        .cloned(),
                );
                let id = format!(
                    "login-{}",
                    self.login_count.fetch_add(1, Ordering::Relaxed) + 1
                );
                let line = match provider.method {
                    Method::Device => {
                        let started =
                            identity::device_start(self.http.as_ref(), &provider, &client, &scopes)
                                .await
                                .map_err(|why| {
                                    Error::Unavailable(format!(
                                        "the sign-in with {} did not start: {why}",
                                        provider.name
                                    ))
                                })?;
                        let line =
                            format!("{id}: open {} and enter {}", started.url, started.user_code);
                        self.shown(
                            &id,
                            &provider,
                            started.url.clone(),
                            Some(started.user_code.clone()),
                            started.expires_at,
                        );
                        let (me, id) = (self.clone(), id.clone());
                        tokio::spawn(async move {
                            let got = identity::device_finish(
                                me.http.as_ref(),
                                &provider,
                                &client,
                                &started,
                                me.poll_wait,
                            )
                            .await;
                            me.finished(&id, &provider, &scopes, got).await;
                        });
                        line
                    }
                    Method::Browser => {
                        let started =
                            identity::browser_start(&provider, &client, &scopes, self.login_within)
                                .await
                                .map_err(|why| {
                                    Error::Unavailable(format!(
                                        "the sign-in with {} did not start: {why}",
                                        provider.name
                                    ))
                                })?;
                        let line =
                            format!("{id}: open {} in a browser on this machine", started.url);
                        self.shown(
                            &id,
                            &provider,
                            started.url.clone(),
                            None,
                            started.expires_at,
                        );
                        let (me, id) = (self.clone(), id.clone());
                        tokio::spawn(async move {
                            let got = identity::browser_finish(
                                me.http.as_ref(),
                                &provider,
                                &client,
                                started,
                            )
                            .await;
                            me.finished(&id, &provider, &scopes, got).await;
                        });
                        line
                    }
                };
                Ok(line)
            }
            LOGOUT => {
                let i: AccountInput = input(command, payload)?;
                let mut book = self.book.lock().await;
                book.remove(&i.account)
                    .ok_or_else(|| Error::NotFound(format!("there is no account {}", i.account)))?;
                self.write(&book)?;
                drop(book);
                self.changed();
                Ok(format!("{} forgotten", i.account))
            }
            other => Err(Error::Invalid(format!(
                "{other} is not a command of {PLUGIN}"
            ))),
        }
    }

    fn shown(
        &self,
        id: &str,
        p: &Provider,
        url: String,
        user_code: Option<String>,
        expires_at: SystemTime,
    ) {
        self.logins.lock().unwrap().insert(
            id.to_string(),
            Login {
                provider: p.name.clone(),
                method: p.method,
                url,
                user_code,
                expires_at,
            },
        );
        self.changed();
    }

    async fn finished(
        &self,
        id: &str,
        p: &Provider,
        asked: &[String],
        got: Result<identity::Tokens, String>,
    ) {
        let kept = match got {
            Ok(t) => match (t.username, t.refresh_token) {
                (Some(username), Some(refresh_token)) => {
                    let account = Account {
                        id: format!("{}:{username}", p.name),
                        provider: p.name.clone(),
                        username,
                        scopes: t.scopes.unwrap_or_else(|| asked.to_vec()),
                        refresh_token,
                    };
                    let mut book = self.book.lock().await;
                    let live = Live {
                        access_token: t.access_token,
                        expires_at: t.expires_at,
                    };
                    let aid = account.id.clone();
                    book.signed_in(account, live);
                    self.write(&book).map(|_| aid).map_err(|e| message(&e))
                }
                (None, _) => Err(format!("{} did not say who signed in", p.name)),
                (_, None) => Err(format!("{} gave no token that renews", p.name)),
            },
            Err(why) => Err(why),
        };
        self.logins.lock().unwrap().remove(id);
        self.changed();
        match kept {
            Ok(account) => {
                let line = format!("{account} signed in");
                self.occurred(SIGNED_IN, 10, line.clone(), json!({ "schema": SCHEMA, "line": line, "login": id, "account": account, "provider": p.name }));
            }
            Err(why) => {
                let line = format!("the sign-in with {} failed: {why}", p.name);
                self.occurred(
                    LOGIN_FAILED,
                    30,
                    line.clone(),
                    json!({ "schema": SCHEMA, "line": line, "login": id, "provider": p.name }),
                );
            }
        }
    }
}

/// Answers a question or carries out a command the Session brought.
pub async fn handle(
    u: &impl Acts,
    event: &Event,
    o: &Arc<Online>,
) -> Result<(), yoke_sdk::base::Error> {
    match event {
        Event::Question(q) if QUERIES.contains(&q.r#type.as_str()) => {
            match o.answer(&q.asker, &q.r#type, &q.payload).await {
                Ok(answer) => u.answer(q, answer).await,
                Err(e) => u.fail(q, code(&e), &message(&e)).await,
            }
        }
        Event::Command(c) if COMMANDS.contains(&c.r#type.as_str()) => {
            match o.act(&c.r#type, &c.payload).await {
                Ok(line) => u.ack(c, Outcome::Done, &line).await.and(o.publish(u).await),
                Err(e) => {
                    u.ack(
                        c,
                        Outcome::Failed,
                        &format!("{}: {}", code(&e), message(&e)),
                    )
                    .await
                }
            }
        }
        _ => Ok(()),
    }
}

/// What happened, carried on the Session: the record published, an occurrence reported.
pub async fn carry(u: &impl Acts, o: &Online, h: Happened) -> Result<(), yoke_sdk::base::Error> {
    match h {
        Happened::Changed => o.publish(u).await,
        Happened::Occurred {
            occurrence,
            severity,
            line,
            detail,
        } => u.report(occurrence, severity, &line, detail).await,
    }
}
