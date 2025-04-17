mod secretstore;

#[cfg(test)]
mod test_lib;

// re-exports
pub use crate::secretstore::{SecretStore, SecretStoreCreator};
