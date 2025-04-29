# Data Format Description

The secret file data has a relatively simple format, consisting of a stream of fixed and variable-size fields. Variable-size fields are prefixed by their size.

In this description `[n]` denotes a field of `n` bytes.

```
- Header
  [2] Magic bytes, constant "5353"
  [1] Format Version. Supported value: 1.
- Nonsecret Data section
  [1] Nonsecret data len, in bytes, 0 -- 255
  [N] Nonsecret data
  Encrypted Secret Data section
  [1] Encryption Version. Supported values: 2 "Scrypt", and 3 "ChaCha", and
      for backwards compatibility: 1 "XOR".
- Version-dependent Encrypted data, see separately below.
  [16] Encryption Salt
  [2] Encrypted Secret Data len, 2 bytes, big endian. Valid range: 1 -- 65535
  [N] Encrypted Secret Data
- Checksum
  [4] Cheksum, of all the previous bytes. First 4 bytes of SHA256D hash.
```

The default encryption version for new data is 2 "Scrypt".

Encryption Version 3: "ChaCha"-encrypted data (XChaCha20Poly1305)
```
- [1]  Number of Log2 rounds (e.g. 13)
  [16] Encryption Salt
  [24] Encryption Nonce
  [2] Encrypted Secret Data len, 2 bytes, big endian. Valid range: 1 -- 65535
  [N] Encrypted Secret Data
```

Encryption Version 2: "Scrypt"-encrypted data (XOR with Scrypt key)
```
- [1]  Number of Log2 rounds (e.g. 14)
  [16] Encryption Salt
  [2] Encrypted Secret Data len, 2 bytes, big endian. Valid range: 1 -- 65535
  [N] Encrypted Secret Data
```

Encryption Version 1: DEPRECATED "XOR" encrypted data
```
  [16] Encryption Salt
  [2] Encrypted Secret Data len, 2 bytes, big endian. Valid range: 1 -- 65535
  [N] Encrypted Secret Data
```

A concrete example, using Scrypt encryption, with each field on separate lines (hex):

```
5353      Magic bytes
01        Format version
03        Nonsecret data len
010203    Nonsecret data
02        Encryption version
0e        Rounds
24799f2ebaf27d4cd517136dd57ad71b  Salt
0800      Encrypted data len (on 2 bytes, value 8)
b44fe9ca543c2f4d  Encrypted data
d8349e1b  Checksum
```
