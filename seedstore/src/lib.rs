// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the  MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// You may not use this file except in accordance with the license.

//! SeedStore is a solution for storing some bitcoin-related secret data
//! in a password-protected encrypted file.
//! A typical example is a wallet storing the secret seed.

mod seedstore;

#[cfg(test)]
mod test_lib;

// re-exports
pub use crate::seedstore::{SeedStore, SeedStoreCreator};
