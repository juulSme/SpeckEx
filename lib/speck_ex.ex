defmodule SpeckEx do
  @moduledoc """
  A Rust-backed implementation of the Speck block cipher with CTR mode of operation.

  This module provides high-level encryption and decryption functions using CTR
  (Counter) mode. For low-level block cipher primitives, see `SpeckEx.Block`.

  ## Supported Variants

  Speck variants with 32, 64 and 128 bits block sizes are supported. The default is Speck128/256 (128-bit block, 256-bit key).

  - `:speck32_64` - 32-bit block, 64-bit key (4-byte block, 8-byte key)
  - `:speck64_96` - 64-bit block, 96-bit key (8-byte block, 12-byte key)
  - `:speck64_128` - 64-bit block, 128-bit key (8-byte block, 16-byte key)
  - `:speck128_128` - 128-bit block, 128-bit key (16-byte block, 16-byte key)
  - `:speck128_192` - 128-bit block, 192-bit key (16-byte block, 24-byte key)
  - `:speck128_256` - 128-bit block, 256-bit key (16-byte block, 32-byte key)

  The remaining variants have block sizes (48 and 96 bits) that are not supported by Rust's `ctr` crate.
  Their primitives are available in `SpeckEx.Block`.

  ## Usage

      # Generate a random key
      key = :crypto.strong_rand_bytes(16)

      # Generate a random nonce (should be unique per encryption with the same key)
      nonce = :crypto.strong_rand_bytes(16)

      # Encrypt data
      ciphertext = SpeckEx.encrypt("Hello, World!", key, nonce)

      # Decrypt data
      plaintext = SpeckEx.decrypt(ciphertext, key, nonce)

      # Use a different variant
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      ciphertext = SpeckEx.encrypt("Hello, World!", key, nonce, variant: :speck128_256)
      plaintext = SpeckEx.decrypt(ciphertext, key, nonce, variant: :speck128_256)

  ## Security Notes

  - **Never reuse a nonce with the same key**. Each encryption must use a unique nonce.
  - Use `:crypto.strong_rand_bytes/1` to generate cryptographically secure random nonces.
  - The nonce should be the same length as the block size of the variant.
  """

  alias SpeckEx.{Block, Native}

  @default_variant :speck128_256

  @doc """
  Encrypts data using CTR mode.

  ## Parameters
  - `plaintext` - The data to encrypt (binary of any length)
  - `key` - The encryption key (length must match the variant's key size)
  - `nonce` - The nonce/IV (length must match the variant's block size)
  - `opts` - Options keyword list
    - `:variant` - The Speck variant to use (default: `:speck128_256`)

  ## Returns
  The encrypted ciphertext as a binary.

  ## Examples

      key = :crypto.strong_rand_bytes(16)
      nonce = :crypto.strong_rand_bytes(16)
      ciphertext = SpeckEx.encrypt("Hello, World!", key, nonce)
  """
  def encrypt(plaintext, key, nonce, opts \\ [])
      when is_binary(plaintext) and is_binary(key) and is_binary(nonce) do
    variant = Keyword.get(opts, :variant, @default_variant)

    {block_size_bits, key_size_bits} = Block.variants() |> Map.fetch!(variant)

    unless bit_size(nonce) == block_size_bits do
      raise ArgumentError, "nonce must be #{block_size_bits} bits for #{variant}"
    end

    unless bit_size(key) == key_size_bits do
      raise ArgumentError, "key must be #{key_size_bits} bits for #{variant}"
    end

    ctr_encrypt(variant, key, nonce, plaintext)
  end

  @doc """
  Decrypts data using CTR mode.

  ## Parameters
  - `ciphertext` - The data to decrypt (binary of any length)
  - `key` - The encryption key (must be the same key used for encryption)
  - `nonce` - The nonce/IV (must be the same nonce used for encryption)
  - `opts` - Options keyword list
    - `:variant` - The Speck variant to use (default: `:speck128_256`)

  ## Returns
  The decrypted plaintext as a binary.

  ## Examples

      plaintext = SpeckEx.decrypt(ciphertext, key, nonce)
  """
  def decrypt(ciphertext, key, nonce, opts \\ [])
      when is_binary(ciphertext) and is_binary(key) and is_binary(nonce) do
    variant = Keyword.get(opts, :variant, @default_variant)
    {block_size_bits, key_size_bits} = Block.variants() |> Map.fetch!(variant)

    unless bit_size(nonce) == block_size_bits do
      raise ArgumentError, "nonce must be #{block_size_bits} bits for #{variant}"
    end

    unless bit_size(key) == key_size_bits do
      raise ArgumentError, "key must be #{key_size_bits} bits for #{variant}"
    end

    ctr_decrypt(variant, key, nonce, ciphertext)
  end

  # Call the appropriate Rust NIF for CTR encryption
  defp ctr_encrypt(variant, key, nonce, data) do
    case variant do
      :speck32_64 -> Native.speck32_64_ctr_encrypt(key, nonce, data)
      :speck64_96 -> Native.speck64_96_ctr_encrypt(key, nonce, data)
      :speck64_128 -> Native.speck64_128_ctr_encrypt(key, nonce, data)
      :speck128_128 -> Native.speck128_128_ctr_encrypt(key, nonce, data)
      :speck128_192 -> Native.speck128_192_ctr_encrypt(key, nonce, data)
      :speck128_256 -> Native.speck128_256_ctr_encrypt(key, nonce, data)
      _ -> raise ArgumentError, "unsupported variant: #{inspect(variant)}"
    end
  end

  # Call the appropriate Rust NIF for CTR decryption
  defp ctr_decrypt(variant, key, nonce, data) do
    case variant do
      :speck32_64 -> Native.speck32_64_ctr_decrypt(key, nonce, data)
      :speck64_96 -> Native.speck64_96_ctr_decrypt(key, nonce, data)
      :speck64_128 -> Native.speck64_128_ctr_decrypt(key, nonce, data)
      :speck128_128 -> Native.speck128_128_ctr_decrypt(key, nonce, data)
      :speck128_192 -> Native.speck128_192_ctr_decrypt(key, nonce, data)
      :speck128_256 -> Native.speck128_256_ctr_decrypt(key, nonce, data)
      _ -> raise ArgumentError, "unsupported variant: #{inspect(variant)}"
    end
  end
end
