# SeedStore: Store bitcoin-related secret material in an encrypted file

__!!!ForeWarning!!!__: Storing valuable secret material on a general-purpose connected computer, laptop, or mobile phone is dangerous, even in ecrypted files! Use it at your own discretion.

Some software needs to store some sensitive secret information. A typical example is a bitcoin hot wallet keeping the wallet seed. Other examples are a Cashu wallet or a Nostr-aware app.

Whenever possible, use solutions where the secrets reside in another, more secure place: a hardware wallet for a bitcoin wallet, or a nostr signer for Nostr.

However, in some scenarios you want to store your own secret. `SeedStore` offer some help here. It stored a small secret in an ecrypted file, protected by an encryption password.


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

- add version
- use zeroize
- for sha256 use bitcon_hashes crate instead of sha256
- document format
- use and store random salt
- (secretstore) use diffrerent encryption (chacha20)
- feature for direct access to secrets
- enforce restricted permissions on the file
- enforce password criteria


## Usage Example

TODO


## Usage Guide

`SeedStore` is a simple Rust library. To compile it, use the usual Rust commands.

```
git clone https://github.com/optout21/seedstore.git
```

```
cargo test
```

_MSRV_: Rust 1.81 (due to fs::exists)
