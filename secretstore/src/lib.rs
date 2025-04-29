// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the  MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// You may not use this file except in accordance with the license.

//! SecretStore is a generic solution for storing some small secret data
//! in a password-protected encrypted file.
//! A typical example is a wallet storing the secret seed.

mod encrypt_chacha;
mod encrypt_common;
mod encrypt_scrypt;
mod encrypt_xor;
mod secretstore;

#[cfg(test)]
mod test_lib;

// re-exports
pub use crate::secretstore::{SecretStore, SecretStoreCreator};
