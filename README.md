# SpeckEx

A high-performance Elixir library for the Speck block cipher, powered by Rust NIFs.
Provides Speck in three modes: high-level CTR mode encryption, authenticated encryption in the form of Speck-Poly1305 and the primitive block cipher.

**This package is in an experimental state. It has not been audited or reviewed, and its backing Rust packages haven't either. The AEAD-mode in particular, combining Speck and Poly1305, is running dangerously close to "rolling your own encryption". Use at your own risk.**

[![License](https://img.shields.io/badge/license-Apache-blue.svg)](LICENSE.md)

## Features

- 🚀 **High Performance**: Rust-backed implementation using NIFs for maximum speed
- 🔐 **Complete**: All 10 Speck cipher variants supported
- 🎯 **Multiple Modes**: Low-level block operations, CTR mode, and AEAD (Speck-Poly1305)
- ✅ **Well Tested**: Comprehensive test suite with official test vectors

## Supported Variants

| Variant        | Block Size         | Key Size           | CTR/AEAD Mode Support |
| -------------- | ------------------ | ------------------ | --------------------- |
| `speck32_64`   | 32-bit (4 bytes)   | 64-bit (8 bytes)   | ⚠️                    |
| `speck48_72`   | 48-bit (6 bytes)   | 72-bit (9 bytes)   | ❌                    |
| `speck48_96`   | 48-bit (6 bytes)   | 96-bit (12 bytes)  | ❌                    |
| `speck64_96`   | 64-bit (8 bytes)   | 96-bit (12 bytes)  | ⚠️                    |
| `speck64_128`  | 64-bit (8 bytes)   | 128-bit (16 bytes) | ⚠️                    |
| `speck96_96`   | 96-bit (12 bytes)  | 96-bit (12 bytes)  | ❌                    |
| `speck96_144`  | 96-bit (12 bytes)  | 144-bit (18 bytes) | ❌                    |
| `speck128_128` | 128-bit (16 bytes) | 128-bit (16 bytes) | ✅                    |
| `speck128_192` | 128-bit (16 bytes) | 192-bit (24 bytes) | ✅                    |
| `speck128_256` | 128-bit (16 bytes) | 256-bit (32 bytes) | ✅ (default)          |

**Note**: CTR and AEAD modes are only available for variants with standard block sizes (32, 64 and 128 bits) due to Rust `ctr` crate limitations. All variants support low-level block operations.
Because using 32 and 64 bits variants with CTR and AEAD modes is a very tricky proposition, they are unsupported through the main entrypoint module, and only available through the `SpeckEx.CTR` and `SpeckEx.AEAD` modules. You should _not_ use them unless you have an exceedingly good reason to do so and you know what you are doing. You have been warned.

## Installation

Add `speck_ex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:speck_ex, "~> 0.0.1"}
  ]
end
```

Documentation can be found on [hexdocs.pm](https://hexdocs.pm/speck_ex/).

### Precompiled binaries

SpeckEx includes precompiled NIFs for most common architectures (Linux, macOS, Windows on x86_64, ARM64, etc.). The Rust toolchain is **not required** for typical installations.

If you're on an unsupported platform, Rustler will automatically compile from source during installation, which requires the Rust toolchain.

## Quick Start

### High-Level CTR Mode Encryption

```elixir
# Generate a random key
key = :crypto.strong_rand_bytes(32)    # 256-bit key

# Encrypt data - nonce is automatically generated and returned
plaintext = "Hello, World! This is a secret message."
{nonce, ciphertext} = SpeckEx.crypt(plaintext, key)

# Decrypt data - provide the nonce from encryption
{_nonce, decrypted} = SpeckEx.crypt(ciphertext, key, nonce: nonce)
# => "Hello, World! This is a secret message."

# Or manually provide a nonce (12 bytes)
nonce = :crypto.strong_rand_bytes(12)
{^nonce, ciphertext} = SpeckEx.crypt(plaintext, key, nonce: nonce)
```

### Authenticated Encryption (AEAD)

Speck-Poly1305 provides authenticated encryption, which protects both the confidentiality and integrity of your data.

```elixir
# Generate a random key
key = :crypto.strong_rand_bytes(32)
aad = "user_id:12345" # Optional associated data (authenticated but not encrypted)

# Encrypt and authenticate - nonce is automatically generated and returned
{nonce, ciphertext, tag} = SpeckEx.aead_encrypt("Secret message", key, aad: aad)

# Verify and decrypt
{:ok, plaintext} = SpeckEx.aead_decrypt(ciphertext, tag, key, nonce, aad: aad)
# => {:ok, "Secret message"}

# Or manually provide a nonce (12 bytes)
nonce = :crypto.strong_rand_bytes(12)
{^nonce, ciphertext, tag} = SpeckEx.aead_encrypt("Secret message", key, nonce: nonce, aad: aad)
```

### Using Different Variants

```elixir
# Speck128/128 (smaller key)
key = :crypto.strong_rand_bytes(16)
{nonce, ciphertext} = SpeckEx.crypt("Secret data", key, variant: :speck128_128)

# Note: Speck variants with smaller block sizes are not available via the main module.
```

### Advanced Usage: Low-Level Modules

For advanced users who need more control, SpeckEx provides low-level modules:

- `SpeckEx.Block` - Direct block cipher operations (all variants)
- `SpeckEx.CTR` - CTR mode for block sizes 32, 64, 128 bits
- `SpeckEx.AEAD` - AEAD mode for block sizes 32, 64, 128 bits

**These modules have no safety guardrails.** You must manage nonces correctly (full block size), understand counter space partitioning, and be aware of birthday bounds for smaller block sizes. Use the main `SpeckEx` module unless you have specific requirements and know what you're doing.

## Security Considerations

⚠️ **Important Security Notes**:

1. **Read the documentation**: You are strongly encouraged to read the comprehensive security guidelines in the `m:SpeckEx#module-security-guidelines` module documentation.

1. **Use the main module**: The `SpeckEx` module provides important safety features including automatic nonce generation, proper counter space partitioning, and limiting access to only 128-bit block variants. Use `SpeckEx.CTR`, `SpeckEx.AEAD`, or `SpeckEx.Block` only if you have specific requirements and understand the risks.

1. **Encryption limits**: Don't encrypt more than 64 GiB with the same nonce. Cycle your key after 4 billion messages to avoid birthday bound issues.

1. **Speck Cipher Status**: Speck is an NSA-designed cipher optimized for performance on constrained devices. While no practical attacks are known, it has received less academic scrutiny than AES. Consider your threat model carefully - the authors themselves recommend AES whenever the available compute resources allow it.

## Performance

SpeckEx leverages Rust NIFs for near-native performance. Speck is designed to be one of the fastest software ciphers, particularly on resource-constrained devices.

```
# AMD Ryzen AI 9 HX 375, Fedora 43

AES 128/256 block dec:            10_388_586 ops/s
AES 128/256 block enc:            10_230_587 ops/s
Speck 64/128 block dec:            9_060_300 ops/s
Speck 128/256 block enc:           8_921_293 ops/s
Speck 64/128 block enc:            8_806_018 ops/s
Speck 128/256 block dec:           8_651_637 ops/s
Blowfish 64/128 block enc:         7_985_090 ops/s
Blowfish 64/128 block dec:         7_628_045 ops/s
Speck 96/144 block enc:            7_482_359 ops/s
Speck 96/144 block dec:            6_736_502 ops/s
Speck 128/256 init + block enc:    3_011_647 ops/s
AES 128/256 init + block enc:      2_823_029 ops/s
AES 128/256 AEAD 1K blocks enc:      648_185 ops/s
AES 128/256 CTR 1K blocks enc:       474_121 ops/s
Speck 128/256 CTR 1K blocks enc:      53_783 ops/s
Blowfish 64/128 init + block enc:     47_983 ops/s
Speck 128/256 AEAD 1K blocks enc:     45_199 ops/s
```

```
# Raspberry Pi 4, Raspbian 5 (Bookworm)

Speck 64/128 block enc:           1_152_034 ops/s
Speck 64/128 block dec:           1_139_208 ops/s
Speck 128/256 block dec:          1_133_155 ops/s
Speck 128/256 block enc:          1_092_916 ops/s
Speck 96/144 block enc:           1_086_639 ops/s
Speck 96/144 block dec:           1_044_686 ops/s
Blowfish 64/128 block enc:          889_855 ops/s
Blowfish 64/128 block dec:          865_773 ops/s
AES 128/256 block enc:              687_009 ops/s
AES 128/256 block dec:              604_879 ops/s
Speck 128/256 init + block enc:     329_179 ops/s
AES 128/256 init + block enc:       176_190 ops/s
Blowfish 64/128 init + block enc:    13_246 ops/s
Speck 128/256 CTR 1K blocks enc:      7_894 ops/s
Speck 128/256 AEAD 1K blocks enc:     6_363 ops/s
AES 128/256 CTR 1K blocks enc:        4_950 ops/s
AES 128/256 AEAD 1K blocks enc:       2_918 ops/s
```

All single thread runs. Run benchmarks with `mix run benchmark/speck.exs`. Notes:

- The "init + block" runs are `:crypto.crypto_one_time/4` equivalents.
- The "block" results are attained _after_ initiation, so `:crypto.crypto_update/2` equivalent.
- The "CTR" results represent init + encrypting 16KB.
- The "AEAD" results represent init + encrypting + poly1305 16KB.
- Blowfish is notoriously slow to initialize and it shows.
- If you encrypt many small things with a different key (so you init every time), Speck is particularly quick.
- If you have AES hardware acceleration you should use AES.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE.md) file for details.

## References

- [Speck Cipher Specification](https://nsacyber.github.io/simon-speck/)
- [IACR ePrint Archive: The SIMON and SPECK Families of Lightweight Block Ciphers](https://eprint.iacr.org/2013/404)
- [Rust speck-cipher crate](https://crates.io/crates/speck-cipher)
- [RustCrypto cipher traits](https://github.com/RustCrypto/traits)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## Acknowledgments

- Built with [Rustler](https://github.com/rusterlium/rustler) for Elixir-Rust interoperability
- Uses the [RustCrypto](https://github.com/RustCrypto) cipher traits and implementations
