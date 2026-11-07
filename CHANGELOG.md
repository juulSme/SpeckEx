# Changelog

## 0.3.0

### Changed

- The high-level AEAD API now limits plaintext and ciphertext to 64 GiB minus 32 bytes per message. Larger inputs raise `ArgumentError`.
- CTR and AEAD operations use dirty CPU schedulers for inputs of at least 16 KiB; AEAD also uses them when associated data reaches that size. Smaller operations remain on normal schedulers.
- Updated Rust and Elixir dependencies and added Elixir 1.20 to the CI test matrix. Elixir 1.18+ and OTP 27+ are fully supported; older supported versions are tested on a best-effort basis.
- Updated benchmarks to compare operations around the dirty scheduler threshold.

### Security

- Clear derived Poly1305 keys and enable zeroization of Speck, CTR, and Poly1305 state when dropped. This does not clear input binaries owned by the BEAM.

### Fixed

- Made AEAD authentication tests deterministic and added coverage for large CTR and AEAD inputs.

## 0.2.0

- Updated dependencies and adapted the Rust implementation to released RustCrypto APIs.
- Simplified tests and fixed a documentation typo.

## 0.1.0

- Initial release.
