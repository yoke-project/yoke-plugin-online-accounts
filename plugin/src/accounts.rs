//! The accounts: who signed in with which provider, and the refresh token each one renews with. They rest
//! in the secret `tokens`, which this unit rewrites itself: a copy of the instance carries none of them, and
//! the unit is not restarted for its own write. Access tokens are held in memory alone.
//!
//! Which asker is given which account is the unit's arguments' to say ([`Give`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// The format of the secret `tokens`.
pub const TOKENS_SCHEMA: u32 = 1;

/// One account: the identity `<provider>:<username>`, the scopes it was granted, and its refresh token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub id: String,
    pub provider: String,
    pub username: String,
    pub scopes: Vec<String>,
    pub refresh_token: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokensFile {
    schema: u32,
    accounts: Vec<Account>,
}

/// Where an account stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Its access token is good for longer than the renewal margin.
    Valid,
    /// Its access token runs out within the margin, or it has none, and it has not been renewed yet.
    Expiring,
    /// The provider no longer honours its grant: the person must sign in again.
    SignInAgain,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Valid => "valid",
            State::Expiring => "expiring",
            State::SignInAgain => "sign_in_again",
        }
    }
}

/// An access token, held in memory.
#[derive(Debug, Clone)]
pub struct Live {
    pub access_token: String,
    pub expires_at: SystemTime,
}

/// The secret `tokens`: read at start, rewritten at every change.
pub struct Tokens {
    path: PathBuf,
}

impl Tokens {
    pub fn at(path: impl Into<PathBuf>) -> Tokens {
        Tokens { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The accounts the secret holds. A value with nothing in it holds none: that is how a deployment
    /// supplies the secret before anyone has signed in.
    pub fn read(&self) -> Result<Vec<Account>, String> {
        let text = std::fs::read_to_string(&self.path)
            .map_err(|e| format!("the secret tokens cannot be read: {e}"))?;
        if text.trim().is_empty() || text.trim() == "{}" {
            return Ok(vec![]);
        }
        let file: TokensFile = serde_json::from_str(&text)
            .map_err(|e| format!("the secret tokens is not what this Plugin writes: {e}"))?;
        if file.schema != TOKENS_SCHEMA {
            return Err(format!(
                "the secret tokens is of schema {}, and this Plugin reads {TOKENS_SCHEMA}",
                file.schema
            ));
        }
        Ok(file.accounts)
    }

    /// Replaces the value with these accounts, in place.
    pub fn write(&self, accounts: &[Account]) -> Result<(), String> {
        let file = TokensFile {
            schema: TOKENS_SCHEMA,
            accounts: accounts.to_vec(),
        };
        let text = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;
        yoke_sdk::plugin::rewrite(&self.path, &text)
            .map_err(|e| format!("the secret tokens cannot be rewritten: {e}"))
    }
}

/// Which asker is given which account, from `--give <asker>=<account>[,<account>…]`. An account is named
/// by its identity, by `<provider>:*`, or `*` for every one; an asker by what the Core says asked —
/// `unit:<unit>`, `channel:<name>`, `operator:<person>` — or `*` for anyone. With no `--give` at all every
/// asker is given every account: a desktop of one person, where the units that ask are that person's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Give(BTreeMap<String, Vec<String>>);

impl Give {
    pub fn add(&mut self, rule: &str) -> Result<(), String> {
        let (asker, accounts) = rule
            .split_once('=')
            .ok_or_else(|| format!("--give takes <asker>=<accounts>, and {rule} is not one"))?;
        if asker.is_empty() || accounts.is_empty() {
            return Err(format!(
                "--give takes <asker>=<accounts>, and {rule} is not one"
            ));
        }
        self.0
            .entry(asker.to_string())
            .or_default()
            .extend(accounts.split(',').map(str::to_string));
        Ok(())
    }

    pub fn may(&self, asker: &str, account: &Account) -> bool {
        if self.0.is_empty() {
            return true;
        }
        let names =
            |a: &String| a == "*" || *a == account.id || *a == format!("{}:*", account.provider);
        [asker, "*"]
            .iter()
            .filter_map(|k| self.0.get(*k))
            .any(|list| list.iter().any(names))
    }
}

/// The accounts and what is known of each in memory.
#[derive(Debug, Default)]
pub struct Book {
    pub accounts: Vec<Account>,
    pub live: BTreeMap<String, Live>,
    /// The accounts whose grant the provider refused, with what it said.
    pub refused: BTreeMap<String, String>,
}

impl Book {
    pub fn get(&self, id: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.id == id)
    }

    pub fn state(&self, id: &str, margin: std::time::Duration, now: SystemTime) -> State {
        if self.refused.contains_key(id) {
            return State::SignInAgain;
        }
        match self.live.get(id) {
            Some(l) if l.expires_at > now + margin => State::Valid,
            _ => State::Expiring,
        }
    }

    /// An account signed in: added, or where it already was, its grant replaced.
    pub fn signed_in(&mut self, account: Account, live: Live) {
        self.refused.remove(&account.id);
        self.live.insert(account.id.clone(), live);
        match self.accounts.iter_mut().find(|a| a.id == account.id) {
            Some(a) => *a = account,
            None => self.accounts.push(account),
        }
    }

    pub fn remove(&mut self, id: &str) -> Option<Account> {
        let at = self.accounts.iter().position(|a| a.id == id)?;
        self.live.remove(id);
        self.refused.remove(id);
        Some(self.accounts.remove(at))
    }
}
