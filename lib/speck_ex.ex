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

      # Generate a random iv (should be unique per encryption with the same key)
      iv = :crypto.strong_rand_bytes(16)

      # Encrypt data
      ciphertext = SpeckEx.encrypt("Hello, World!", key, iv)

      # Decrypt data
      plaintext = SpeckEx.decrypt(ciphertext, key, iv)

      # Use a different variant
      key = :crypto.strong_rand_bytes(32)
      iv = :crypto.strong_rand_bytes(16)
      ciphertext = SpeckEx.encrypt("Hello, World!", key, iv, variant: :speck128_256)
      plaintext = SpeckEx.decrypt(ciphertext, key, iv, variant: :speck128_256)

  ## Security Notes

  - **Never reuse a iv with the same key**. Each encryption must use a unique iv.
  - Use `:crypto.strong_rand_bytes/1` to generate cryptographically secure random ivs.
  - The iv should be the same length as the block size of the variant.
  """
  alias SpeckEx.{Block, Native}
  import Native

  @variants Block.variants()
            |> Enum.filter(fn {_, {block_size, _}} -> block_size in [32, 64, 128] end)
            |> Map.new()

  @default_variant :speck128_256

  @typedoc """
  Supported Speck variants. Naming: `speck<block_size>_<key_size>`, sizes in bits.
  """
  @type variants ::
          :speck32_64 | :speck64_96 | :speck64_128 | :speck128_128 | :speck128_192 | :speck128_256

  @doc """
  Encrypts data using CTR mode.

  ## Parameters
  - `plaintext` - The data to encrypt (binary of any length)
  - `key` - The encryption key (length must match the variant's key size)
  - `iv` - The iv (length must match the variant's block size)
  - `variant` - The Speck variant to use (default: `:speck128_256`)

  ## Returns
  The encrypted ciphertext as a binary.

  ## Examples

      key = :crypto.strong_rand_bytes(16)
      iv = :crypto.strong_rand_bytes(16)
      ciphertext = SpeckEx.encrypt("Hello, World!", key, iv)
  """
  @spec encrypt(binary(), <<_::256>>, <<_::128>>) :: binary()
  def encrypt(plaintext, key, iv, variant \\ @default_variant)

  for {variant, {block_size, key_size}} <- @variants do
    @spec encrypt(
            binary(),
            <<_::unquote(key_size)>>,
            <<_::unquote(block_size)>>,
            unquote(variant)
          ) ::
            binary()
    def encrypt(data, key, iv, unquote(variant))
        when bit_size(iv) == unquote(block_size) and bit_size(key) == unquote(key_size) do
      unquote(:"speck#{block_size}_#{key_size}_ctr_encrypt")(key, iv, data)
    end
  end

  @doc """
  Decrypts data using CTR mode.

  ## Parameters
  - `ciphertext` - The data to decrypt (binary of any length)
  - `key` - The encryption key (must be the same key used for encryption)
  - `iv` - The iv (must be the same iv used for encryption)
  - `variant` - The Speck variant to use (default: `:speck128_256`)

  ## Returns
  The decrypted plaintext as a binary.

  ## Examples

      plaintext = SpeckEx.decrypt(ciphertext, key, iv)
  """
  @spec decrypt(binary(), <<_::256>>, <<_::128>>) :: binary()
  def decrypt(plaintext, key, iv, variant \\ @default_variant)

  for {variant, {block_size, key_size}} <- @variants do
    @spec decrypt(
            binary(),
            <<_::unquote(key_size)>>,
            <<_::unquote(block_size)>>,
            unquote(variant)
          ) ::
            binary()
    def decrypt(data, key, iv, unquote(variant))
        when bit_size(iv) == unquote(block_size) and bit_size(key) == unquote(key_size) do
      unquote(:"speck#{block_size}_#{key_size}_ctr_decrypt")(key, iv, data)
    end
  end

  @doc """
  Returns a map of all supported Speck variants with their block and key sizes.

  ## Returns
  A map where keys are variant atoms and values are tuples of {block_size_bits, key_size_bits}.
  """
  @spec variants() :: %{variants() => Block.variant_parameters()}
  def variants, do: @variants
end
