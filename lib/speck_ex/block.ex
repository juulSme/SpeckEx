defmodule SpeckEx.Block do
  @moduledoc """
  Low-level block cipher primitives for the Speck cipher.

  This module provides generic functions that work with any Speck variant.

  > #### Here be dragons {: .warning}
  >
  > This is a "no guardrails" implementation module of limited practical use. It works with single blocks of data and requires a cipher mode to process anything else. Use the main `SpeckEx` module unless you know what you are doing.

  ## Supported Variants

  - `:speck32_64` - 32-bit block, 64-bit key (4-byte block, 8-byte key)
  - `:speck48_72` - 48-bit block, 72-bit key (6-byte block, 9-byte key)
  - `:speck48_96` - 48-bit block, 96-bit key (6-byte block, 12-byte key)
  - `:speck64_96` - 64-bit block, 96-bit key (8-byte block, 12-byte key)
  - `:speck64_128` - 64-bit block, 128-bit key (8-byte block, 16-byte key)
  - `:speck96_96` - 96-bit block, 96-bit key (12-byte block, 12-byte key)
  - `:speck96_144` - 96-bit block, 144-bit key (12-byte block, 18-byte key)
  - `:speck128_128` - 128-bit block, 128-bit key (16-byte block, 16-byte key)
  - `:speck128_192` - 128-bit block, 192-bit key (16-byte block, 24-byte key)
  - `:speck128_256` - 128-bit block, 256-bit key (16-byte block, 32-byte key)

  ## Usage

      # Initialize cipher
      iex> cipher = SpeckEx.Block.init(:crypto.strong_rand_bytes(32))
      iex> is_reference(cipher)
      true

      # Encrypt a block
      iex> cipher = SpeckEx.Block.init(:crypto.strong_rand_bytes(32))
      iex> ciphertext = SpeckEx.Block.encrypt(<<0::128>>, cipher)
      iex> is_binary(ciphertext) and byte_size(ciphertext) == 16
      true

      # Decrypt a block
      iex> cipher = SpeckEx.Block.init(:crypto.strong_rand_bytes(32))
      iex> ciphertext = SpeckEx.Block.encrypt(<<0::128>>, cipher)
      iex> SpeckEx.Block.decrypt(ciphertext, cipher)
      <<0::128>>
  """
  alias SpeckEx.Native

  @typedoc """
  All supported Speck block cipher variants. Naming: `speck<block_size>_<key_size>`, sizes in bits.

  All variants are supported for low-level block cipher operations. However, only variants
  with 32, 64 and 128-bit block sizes are supported for CTR and AEAD modes.
  """
  @type variant ::
          :speck32_64
          | :speck48_72
          | :speck48_96
          | :speck64_96
          | :speck64_128
          | :speck96_96
          | :speck96_144
          | :speck128_128
          | :speck128_192
          | :speck128_256

  @doc """
  Initialize a Speck cipher with the given key and variant.

  ## Parameters
  - `key` - A binary of the correct size for the variant
  - `variant` - The Speck variant to use (default: `:speck128_256`)

  ## Returns
  A cipher reference resource that can be used for encryption/decryption.

  ## Examples

      iex> cipher = SpeckEx.Block.init(:crypto.strong_rand_bytes(32))
      iex> is_reference(cipher)
      true

  """
  @spec init(binary, variant) :: reference()
  def init(key, variant \\ :speck128_256)
  def init(<<key::binary-8>>, :speck32_64), do: Native.speck32_64_init(key)
  def init(<<key::binary-9>>, :speck48_72), do: Native.speck48_72_init(key)
  def init(<<key::binary-12>>, :speck48_96), do: Native.speck48_96_init(key)
  def init(<<key::binary-12>>, :speck64_96), do: Native.speck64_96_init(key)
  def init(<<key::binary-16>>, :speck64_128), do: Native.speck64_128_init(key)
  def init(<<key::binary-12>>, :speck96_96), do: Native.speck96_96_init(key)
  def init(<<key::binary-18>>, :speck96_144), do: Native.speck96_144_init(key)
  def init(<<key::binary-16>>, :speck128_128), do: Native.speck128_128_init(key)
  def init(<<key::binary-24>>, :speck128_192), do: Native.speck128_192_init(key)
  def init(<<key::binary-32>>, :speck128_256), do: Native.speck128_256_init(key)

  @doc """
  Encrypt a single block using the specified variant.

  ## Parameters
  - `data` - A binary of the correct block size for the variant
  - `cipher_ref` - A cipher reference from `init/2`
  - `variant` - The Speck variant (must match the cipher_ref's variant, default `:speck128_256`)

  ## Returns
  The encrypted block as a binary.

  ## Examples

      iex> cipher = SpeckEx.Block.init(:crypto.strong_rand_bytes(32))
      iex> ciphertext = SpeckEx.Block.encrypt(<<0::128>>, cipher)
      iex> is_binary(ciphertext) and byte_size(ciphertext) == 16
      true

  """
  @spec encrypt(binary, reference(), variant) :: binary
  def encrypt(data, cipher_ref, variant \\ :speck128_256)

  def encrypt(<<data::binary-4>>, cipher_ref, :speck32_64),
    do: Native.speck32_64_encrypt(data, cipher_ref)

  def encrypt(<<data::binary-6>>, cipher_ref, :speck48_72),
    do: Native.speck48_72_encrypt(data, cipher_ref)

  def encrypt(<<data::binary-6>>, cipher_ref, :speck48_96),
    do: Native.speck48_96_encrypt(data, cipher_ref)

  def encrypt(<<data::binary-8>>, cipher_ref, :speck64_96),
    do: Native.speck64_96_encrypt(data, cipher_ref)

  def encrypt(<<data::binary-8>>, cipher_ref, :speck64_128),
    do: Native.speck64_128_encrypt(data, cipher_ref)

  def encrypt(<<data::binary-12>>, cipher_ref, :speck96_96),
    do: Native.speck96_96_encrypt(data, cipher_ref)

  def encrypt(<<data::binary-12>>, cipher_ref, :speck96_144),
    do: Native.speck96_144_encrypt(data, cipher_ref)

  def encrypt(<<data::binary-16>>, cipher_ref, :speck128_128),
    do: Native.speck128_128_encrypt(data, cipher_ref)

  def encrypt(<<data::binary-16>>, cipher_ref, :speck128_192),
    do: Native.speck128_192_encrypt(data, cipher_ref)

  def encrypt(<<data::binary-16>>, cipher_ref, :speck128_256),
    do: Native.speck128_256_encrypt(data, cipher_ref)

  @doc """
  Decrypt a single block using the specified variant.

  ## Parameters
  - `data` - A binary of the correct block size for the variant
  - `cipher_ref` - A cipher reference from `init/2`
  - `variant` - The Speck variant (must match the cipher_ref's variant, default `:speck128_256`)

  ## Returns
  The decrypted block as a binary.

  ## Examples

      iex> cipher = SpeckEx.Block.init(:crypto.strong_rand_bytes(32))
      iex> ciphertext = SpeckEx.Block.encrypt(<<0::128>>, cipher)
      iex> SpeckEx.Block.decrypt(ciphertext, cipher)
      <<0::128>>

  """
  @spec decrypt(binary, reference(), variant) :: binary
  def decrypt(data, cipher_ref, variant \\ :speck128_256)

  def decrypt(<<data::binary-4>>, cipher_ref, :speck32_64),
    do: Native.speck32_64_decrypt(data, cipher_ref)

  def decrypt(<<data::binary-6>>, cipher_ref, :speck48_72),
    do: Native.speck48_72_decrypt(data, cipher_ref)

  def decrypt(<<data::binary-6>>, cipher_ref, :speck48_96),
    do: Native.speck48_96_decrypt(data, cipher_ref)

  def decrypt(<<data::binary-8>>, cipher_ref, :speck64_96),
    do: Native.speck64_96_decrypt(data, cipher_ref)

  def decrypt(<<data::binary-8>>, cipher_ref, :speck64_128),
    do: Native.speck64_128_decrypt(data, cipher_ref)

  def decrypt(<<data::binary-12>>, cipher_ref, :speck96_96),
    do: Native.speck96_96_decrypt(data, cipher_ref)

  def decrypt(<<data::binary-12>>, cipher_ref, :speck96_144),
    do: Native.speck96_144_decrypt(data, cipher_ref)

  def decrypt(<<data::binary-16>>, cipher_ref, :speck128_128),
    do: Native.speck128_128_decrypt(data, cipher_ref)

  def decrypt(<<data::binary-16>>, cipher_ref, :speck128_192),
    do: Native.speck128_192_decrypt(data, cipher_ref)

  def decrypt(<<data::binary-16>>, cipher_ref, :speck128_256),
    do: Native.speck128_256_decrypt(data, cipher_ref)
end
