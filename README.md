# SeedStore: Store bitcoin-related secret material in an encrypted file

__!!!ForeWarning!!!__: Storing valuable secret material on a general-purpose connected computer, laptop, or mobile phone is dangerous, even in ecrypted files! Use it at your own discretion.

Some software needs to store sensitive secret information. A typical example is a bitcoin hot wallet keeping the wallet seed. Other examples are a Cashu wallet or a Nostr-aware app.

Whenever possible, use solutions where the secrets reside in another, more secure place: a hardware wallet for a bitcoin wallet, or a nostr signer for Nostr.

However, in some scenarios you want to store your own secret. `SeedStore` offers some help here. It stores a small secret in an ecrypted file, protected by an encryption password.


## Security considerations

Storing valuable secret material on a general-purpose connected computer (desktop, laptop, or mobile phone) is inherently dangerous. Using encryption only mitigates the problem, but it does not solve it.

Steps to mitigate the risks:

- Use strong encryption password!
- Safeguard your encryption password!
- Don't reuse your passwords!
- Secure your computer
- Use dedicated hardware for sensitive secrets
- Use custom-build hardware for sensitive secrets (signer device, hardware wallet)
- Use proper encryption --- `SeedStore` helps here


## TODO

- passphrase to the seed ?
- direct access to secrets available only in separate feature
- enforce restricted permissions on the file
- encorce strong password
- KeyStore for storing a single key
- version 1.0, with format guarantee


## Usage Example

Reading secret from file:

```
use seedstore::SeedStore;

    let seedstore = SeedStore::new_from_encrypted_file("./sample.secret", "PasswordVEWFVFDHHEBNJS3")?;
    let xpub = seedstore.get_xpub().unwrap();
    let network = seedstore.network();
```

Writing out seed secret:

```
use seedstore::SeedStoreCreator;

    let seedstore = SeedStoreCreator::new_from_data(&entropy_bytes, 0)?;
    SeedStoreCreator::write_to_file(&seedstore, "./sample.secret", "PasswordVEWFVFDHHEBNJS3")?;
}
```

See the [example programs](seedstore/examples).


## Usage Guide

`SeedStore` is a simple Rust library. To compile it, use the usual Rust commands.

```
git clone https://github.com/optout21/seedstore.git
```

```
cargo build
cargo test
cargo run --example create_seedstore
```

_MSRV_: Rust 1.81 (due to `fs::exists`)

## Data Format

The data format of the secret file is documented here: [Data_Format.md](Data_Format.md)

Data format backward compatibility:
This project is committed to stay backward-compatible to files created by any previous version (starting from v1.0).
Later versions may not be able to re-create older formats,
(e.g. due to different default values),
or create older versions at all, but they should be able to READ any older format.

The reading of any secret files created by any previous versions should be supported.

See backward compatibility tests: [compat_backtest.rs](seedstore/src/compat_backtest.rs).

