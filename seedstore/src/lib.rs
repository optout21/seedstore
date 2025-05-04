// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the  MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// You may not use this file except in accordance with the license.

//! [`SeedStore`] is a solution for storing a BIP32-style master secret
//! in a password-protected encrypted file.
//! SeedStore is built on [`secretstore::SecretStore`].
//! A typical example is a wallet storing the secret seed.
//!
//! If only a single key is needed, it it possible to use a single child key, or use [`KeyStore`] for a single key.

mod keystore;
mod seedstore;

#[cfg(feature = "toolhelper")]
mod tool;

#[cfg(test)]
mod compat_backtest;
#[cfg(test)]
mod test_keystore;
#[cfg(test)]
mod test_seedstore;

// re-exports
pub use crate::keystore::{KeyStore, KeyStoreCreator};
pub use crate::seedstore::{ChildSpecifier, SeedStore, SeedStoreCreator};
#[cfg(feature = "toolhelper")]
pub use crate::tool::SeedStoreTool;
