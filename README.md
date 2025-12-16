# SpeckEx

A high-performance Elixir library for the Speck block cipher, powered by Rust NIFs. Provides both low-level block cipher primitives and high-level CTR mode encryption.

Note that the backing Rust crate is a prerelease version at this time.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Features

- 🚀 **High Performance**: Rust-backed implementation using NIFs for maximum speed
- 🔐 **Complete Coverage**: All 10 Speck cipher variants supported
- 🎯 **Multiple Modes**: Low-level block operations and CTR mode for stream encryption
- ✅ **Well Tested**: Comprehensive test suite with official test vectors
- 📚 **Excellent Documentation**: Clear examples and security guidelines
- 🛡️ **Type Safe**: Compile-time validation of key and block sizes

## Supported Variants

| Variant        | Block Size         | Key Size           | CTR Mode Support |
| -------------- | ------------------ | ------------------ | ---------------- |
| `speck32_64`   | 32-bit (4 bytes)   | 64-bit (8 bytes)   | ✅               |
| `speck48_72`   | 48-bit (6 bytes)   | 72-bit (9 bytes)   | ❌               |
| `speck48_96`   | 48-bit (6 bytes)   | 96-bit (12 bytes)  | ❌               |
| `speck64_96`   | 64-bit (8 bytes)   | 96-bit (12 bytes)  | ✅               |
| `speck64_128`  | 64-bit (8 bytes)   | 128-bit (16 bytes) | ✅               |
| `speck96_96`   | 96-bit (12 bytes)  | 96-bit (12 bytes)  | ❌               |
| `speck96_144`  | 96-bit (12 bytes)  | 144-bit (18 bytes) | ❌               |
| `speck128_128` | 128-bit (16 bytes) | 128-bit (16 bytes) | ✅               |
| `speck128_192` | 128-bit (16 bytes) | 192-bit (24 bytes) | ✅               |
| `speck128_256` | 128-bit (16 bytes) | 256-bit (32 bytes) | ✅ (default)     |

**Note**: CTR mode is only available for variants with standard block sizes (32, 64, 128 bits) due to Rust `ctr` crate limitations. All variants support low-level block operations.

## Installation

Add `speck_ex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:speck_ex, "~> 0.1.0"}
  ]
end
```

### Requirements

- Elixir 1.15 or later
- Rust toolchain (for compilation)
- Rustler will automatically compile the Rust NIF during installation

## Quick Start

### High-Level CTR Mode Encryption

```elixir
# Generate a random key and nonce
key = :crypto.strong_rand_bytes(32)    # 256-bit key
nonce = :crypto.strong_rand_bytes(16)  # 128-bit nonce

# Encrypt data
plaintext = "Hello, World! This is a secret message."
ciphertext = SpeckEx.encrypt(plaintext, key, nonce)

# Decrypt data
decrypted = SpeckEx.decrypt(ciphertext, key, nonce)
# => "Hello, World! This is a secret message."
```

### Using Different Variants

```elixir
# Speck128/128 (smaller key)
key = :crypto.strong_rand_bytes(16)
nonce = :crypto.strong_rand_bytes(16)
ciphertext = SpeckEx.encrypt("Secret data", key, nonce, variant: :speck128_128)

# Speck64/128 (smaller block size)
key = :crypto.strong_rand_bytes(16)
nonce = :crypto.strong_rand_bytes(8)   # 64-bit nonce
ciphertext = SpeckEx.encrypt("Secret data", key, nonce, variant: :speck64_128)
```

### Low-Level Block Operations

```elixir
# Initialize cipher
key = :crypto.strong_rand_bytes(16)
cipher = SpeckEx.Block.speck128_128_init!(key)

# Encrypt a single 16-byte block
plaintext_block = :crypto.strong_rand_bytes(16)
ciphertext_block = SpeckEx.Block.speck128_128_encrypt!(plaintext_block, cipher)

# Decrypt the block
decrypted_block = SpeckEx.Block.speck128_128_decrypt!(ciphertext_block, cipher)
```

## Security Considerations

⚠️ **Important Security Notes**:

1. **Never Reuse Nonces**: Each encryption with the same key MUST use a unique nonce. Nonce reuse completely breaks CTR mode security.

2. **Use Cryptographically Secure Random**: Always use `:crypto.strong_rand_bytes/1` for generating keys and nonces.

3. **Speck Cipher Status**: Speck is an NSA-designed cipher optimized for performance on constrained devices. While no practical attacks are known, it has received less academic scrutiny than AES. Consider your threat model carefully.

4. **No Authentication**: This library provides encryption only. For authenticated encryption, combine with HMAC or use a higher-level AEAD construction.

5. **Side-Channel Attacks**: The Rust implementation uses constant-time operations where possible, but has not been audited for side-channel resistance.

## Performance

SpeckEx leverages Rust NIFs for near-native performance. Speck is designed to be one of the fastest software ciphers, particularly on resource-constrained devices.

Typical benchmarks (AMD64):

- Block operations: ~10-20 cycles per byte
- CTR mode: Comparable to AES-NI on modern processors

Run benchmarks with:

```bash
mix run benchmark/speck.exs
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

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
