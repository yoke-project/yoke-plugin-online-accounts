//! Online accounts as a Yoke Plugin: accounts held, signed in and renewed, and their access tokens given to
//! whoever asks and is given them.
//!
//! `identity` knows the providers and speaks to their endpoints, `accounts` keeps the accounts and the secret
//! they rest in, and `plugin` is the Plugin around them.

pub mod accounts;
pub mod identity;
pub mod plugin;
