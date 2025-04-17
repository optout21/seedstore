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
  [1] Encryption Version. Supported value: 1.
  [16] Encryption Salt
  [1] Encrypted Secret Data len minus 1, valid range 1 -- 256
  [N] Encrypted Secret Data
- Checksum
  [4] Cheksum, of all the previous bytes. First 4 bytes of SHA256 hash.
```


