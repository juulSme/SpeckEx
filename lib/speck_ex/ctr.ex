defmodule SpeckEx.CTR do
  @moduledoc """
  Counter (CTR) mode encryption using the Speck block cipher.

  This module provides stream cipher encryption using Speck in CTR mode,
  allowing encryption of data of arbitrary length. CTR mode turns a block
  cipher into a stream cipher by encrypting a counter value.

  > #### Here be dragons {: .warning}
  >
  > This is a "no guardrails" implementation module, where nonce generation is your own responsibility. Use the main `SpeckEx` module unless you know what you are doing. Be sure to read the `m:SpeckEx#module-security-guidelines` security guidelines.

  ## Supported Variants

  Only Speck variants with 32, 64 and 128-bit block sizes are supported because of limitations of the backing Rust "ctr" crate:

  - `:speck32_64` - 32-bit block, 64-bit key (4-byte block, 8-byte key)
  - `:speck64_96` - 64-bit block, 96-bit key (8-byte block, 12-byte key)
  - `:speck64_128` - 64-bit block, 128-bit key (8-byte block, 16-byte key)
  - `:speck128_128` - 128-bit block, 128-bit key (16-byte block, 16-byte key)
  - `:speck128_192` - 128-bit block, 192-bit key (16-byte block, 24-byte key)
  - `:speck128_256` - 128-bit block, 256-bit key (16-byte block, 32-byte key, default)

  ## Usage

      # Generate a random key (32 bytes for default speck128_256)
      iex> key = :crypto.strong_rand_bytes(32)
      iex> nonce = :crypto.strong_rand_bytes(16)
      iex> ciphertext = SpeckEx.CTR.crypt("Secret message", key, nonce)
      iex> SpeckEx.CTR.crypt(ciphertext, key, nonce)
      "Secret message"
  """

  alias SpeckEx.Native

  @typedoc """
  Speck variants with 32, 64 and 128-bit block sizes, supported by CTR and AEAD modes.
  """
  @type variant ::
          :speck32_64 | :speck64_96 | :speck64_128 | :speck128_128 | :speck128_192 | :speck128_256

  @doc """
  En/decrypt using CTR mode.

  ## Parameters

  - `data` - The data to en/decrypt (binary, any length)
  - `key` - The encryption key (size depends on variant)
  - `nonce` - The initialization vector (size depends on variant, MUST be unique per key)
  - `variant` - The Speck variant to use (default: `:speck128_256`)

  ## Returns

  The encrypted ciphertext or decrypted plaintext as a binary (same length as data).

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> nonce = :crypto.strong_rand_bytes(16)
      iex> ciphertext = SpeckEx.CTR.crypt("Hello, World!", key, nonce)
      iex> is_binary(ciphertext) and byte_size(ciphertext) == byte_size("Hello, World!")
      true

  """
  @spec crypt(binary, binary, binary, variant) :: binary
  def crypt(data, key, nonce, variant \\ :speck128_256)

  def crypt(data, <<key::binary-32>>, <<nonce::binary-16>>, :speck128_256),
    do: Native.speck128_256_ctr_crypt(key, nonce, data)

  def crypt(data, <<key::binary-24>>, <<nonce::binary-16>>, :speck128_192),
    do: Native.speck128_192_ctr_crypt(key, nonce, data)

  def crypt(data, <<key::binary-16>>, <<nonce::binary-16>>, :speck128_128),
    do: Native.speck128_128_ctr_crypt(key, nonce, data)

  def crypt(data, <<key::binary-16>>, <<nonce::binary-8>>, :speck64_128),
    do: Native.speck64_128_ctr_crypt(key, nonce, data)

  def crypt(data, <<key::binary-12>>, <<nonce::binary-8>>, :speck64_96),
    do: Native.speck64_96_ctr_crypt(key, nonce, data)

  def crypt(data, <<key::binary-8>>, <<nonce::binary-4>>, :speck32_64),
    do: Native.speck32_64_ctr_crypt(key, nonce, data)
end
