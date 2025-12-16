defmodule SpeckEx do
  @moduledoc """
  A Rust-backed implementation of the Speck block cipher using NIF Resources.

  This module provides direct one-to-one mappings to Rust implementations of
  all Speck cipher variants. Each variant has its own init, encrypt, and decrypt functions.

  ## Supported Variants

  - `speck32_64_init!/1` - 32-bit block, 64-bit key (4-byte block, 8-byte key)
  - `speck48_72_init!/1` - 48-bit block, 72-bit key (6-byte block, 9-byte key)
  - `speck48_96_init!/1` - 48-bit block, 96-bit key (6-byte block, 12-byte key)
  - `speck64_96_init!/1` - 64-bit block, 96-bit key (8-byte block, 12-byte key)
  - `speck64_128_init!/1` - 64-bit block, 128-bit key (8-byte block, 16-byte key)
  - `speck96_96_init!/1` - 96-bit block, 96-bit key (12-byte block, 12-byte key)
  - `speck96_144_init!/1` - 96-bit block, 144-bit key (12-byte block, 18-byte key)
  - `speck128_128_init!/1` - 128-bit block, 128-bit key (16-byte block, 16-byte key)
  - `speck128_192_init!/1` - 128-bit block, 192-bit key (16-byte block, 24-byte key)
  - `speck128_256_init!/1` - 128-bit block, 256-bit key (16-byte block, 32-byte key)

  ## Usage

      # Initialize cipher with key (raises on error)
      cipher = SpeckEx.speck128_128_init!(:crypto.strong_rand_bytes(16))

      # Encrypt a block
      ciphertext = SpeckEx.speck128_128_encrypt!(<<0::128>>, cipher)

      # Decrypt a block
      plaintext = SpeckEx.speck128_128_decrypt!(ciphertext, cipher)
  """

  alias SpeckEx.Native

  @variants [
    speck32_64: {32, 64},
    speck48_72: {48, 72},
    speck48_96: {48, 96},
    speck64_96: {64, 96},
    speck64_128: {64, 128},
    speck96_96: {96, 96},
    speck96_144: {96, 144},
    speck128_128: {128, 128},
    speck128_192: {128, 192},
    speck128_256: {128, 256}
  ]

  for {variant, {block_size, key_size}} <- @variants do
    def unquote(:"#{variant}_init!")(key) when bit_size(key) == unquote(key_size),
      do: Native.unquote(:"#{variant}_init")(key)

    def unquote(:"#{variant}_encrypt!")(data, cipher_ref)
        when bit_size(data) == unquote(block_size),
        do: Native.unquote(:"#{variant}_encrypt")(data, cipher_ref)

    def unquote(:"#{variant}_decrypt!")(data, cipher_ref)
        when bit_size(data) == unquote(block_size),
        do: Native.unquote(:"#{variant}_decrypt")(data, cipher_ref)
  end
end
