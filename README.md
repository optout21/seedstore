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

- 2-byte secret len
- use zeroize
- for sha256 use bitcon_hashes crate instead of sha256
- use diffrerent encryption (chacha20)
- direct access to secrets available only in separate feature
- enforce restricted permissions on the file
- enforce password criteria (min len)
- version 1.0, with format guarantee


## Usage Example

TODO


## Usage Guide

`SeedStore` is a simple Rust library. To compile it, use the usual Rust commands.

```
git clone https://github.com/optout21/seedstore.git
```

```
cargo build
cargo test
```

_MSRV_: Rust 1.81 (due to `fs::exists`)

## Data Format
Secret file data format documentation: [Data_Format.md](Data_Format.md)
