defmodule SpeckEx.AEAD do
  @moduledoc """
  Authenticated Encryption with Associated Data (AEAD) using Speck-Poly1305.

  This module provides authenticated encryption using Speck in CTR mode combined
  with Poly1305 MAC for authentication. This construction provides both
  confidentiality and authenticity, protecting against tampering and forgery.

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
      iex> aad = "user_id:12345"
      iex> {ciphertext, tag} = SpeckEx.AEAD.encrypt("Secret message", key, nonce, aad)
      iex> SpeckEx.AEAD.decrypt(ciphertext, tag, key, nonce, aad)
      {:ok, "Secret message"}

  ## Associated Data (AAD)

  The associated data parameter allows you to authenticate additional data that
  is not encrypted. This is useful for protocol headers, metadata, or any data
  that must be authenticated but not kept confidential.

  - AAD can be empty (`""`)
  - AAD is not included in the ciphertext
  - Modifying AAD will cause authentication to fail

  ## Why Speck-Poly1305

  Most authenticated encryption modes are only defined for 128 bits ciphers,
  which makes sense because they tend to create a verification tag of the block size of the underlying cipher,
  and a 64-bits MAC is too short to be secure.
  By using Poly1305, the MAC (or tag) is always 128 bits regardless of the block size of the cipher used to generate the Poly1305 key.
  This is somewhat sanctioned, at least, by [RFC8439](https://www.rfc-editor.org/rfc/rfc8439#section-2.5):

  > There is nothing special about AES here.  One can replace AES with an arbitrary keyed function from an arbitrary set of nonces to 16-byte strings.
  """

  alias SpeckEx.Native

  @typedoc """
  AEAD mode supports Speck variants with 32, 64 and 128-bit block sizes.
  """
  @type variant :: SpeckEx.CTR.variant()

  @doc """
  Encrypts plaintext and computes an authentication tag.

  Returns a tuple `{ciphertext, tag}` where:
  - `ciphertext` is the encrypted data (same length as plaintext)
  - `tag` is a 16-byte Poly1305 authentication tag

  ## Parameters

  - `plaintext` - The data to encrypt (binary, any length)
  - `key` - The encryption key (size depends on variant)
  - `nonce` - The nonce (size depends on variant, MUST be unique per key)
  - `aad` - Associated authenticated data (binary, any length, can be empty)
  - `variant` - The Speck variant to use (default: `:speck128_256`)

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> nonce = :crypto.strong_rand_bytes(16)
      iex> {ciphertext, tag} = SpeckEx.AEAD.encrypt("Hello", key, nonce, "metadata")
      iex> is_binary(ciphertext) and byte_size(tag) == 16
      true

  """
  @spec encrypt(binary, binary, binary, binary, variant) :: {binary, binary}
  def encrypt(plaintext, key, nonce, aad, variant \\ :speck128_256)

  def encrypt(plaintext, <<key::binary-32>>, <<nonce::binary-16>>, aad, :speck128_256),
    do: Native.speck128_256_poly1305_encrypt(key, nonce, plaintext, aad)

  def encrypt(plaintext, <<key::binary-24>>, <<nonce::binary-16>>, aad, :speck128_192),
    do: Native.speck128_192_poly1305_encrypt(key, nonce, plaintext, aad)

  def encrypt(plaintext, <<key::binary-16>>, <<nonce::binary-16>>, aad, :speck128_128),
    do: Native.speck128_128_poly1305_encrypt(key, nonce, plaintext, aad)

  def encrypt(plaintext, <<key::binary-16>>, <<nonce::binary-8>>, aad, :speck64_128),
    do: Native.speck64_128_poly1305_encrypt(key, nonce, plaintext, aad)

  def encrypt(plaintext, <<key::binary-12>>, <<nonce::binary-8>>, aad, :speck64_96),
    do: Native.speck64_96_poly1305_encrypt(key, nonce, plaintext, aad)

  def encrypt(plaintext, <<key::binary-8>>, <<nonce::binary-4>>, aad, :speck32_64),
    do: Native.speck32_64_poly1305_encrypt(key, nonce, plaintext, aad)

  @doc """
  Verifies the authentication tag and decrypts the ciphertext.

  Returns `{:ok, plaintext}` if authentication succeeds, or
  `{:error, :authentication_failed}` if the tag is invalid.

  ## Parameters

  - `ciphertext` - The encrypted data (binary, any length)
  - `tag` - The 16-byte Poly1305 authentication tag
  - `key` - The encryption key (size depends on variant)
  - `nonce` - The nonce (size depends on variant, must match encryption)
  - `aad` - Associated authenticated data (must match encryption)
  - `variant` - The Speck variant to use (default: `:speck128_256`)

  ## Examples

      # Successful decryption
      iex> key = :crypto.strong_rand_bytes(32)
      iex> nonce = :crypto.strong_rand_bytes(16)
      iex> {ciphertext, tag} = SpeckEx.AEAD.encrypt("Hello", key, nonce, "aad")
      iex> SpeckEx.AEAD.decrypt(ciphertext, tag, key, nonce, "aad")
      {:ok, "Hello"}

      # Failed authentication
      iex> key = :crypto.strong_rand_bytes(32)
      iex> nonce = :crypto.strong_rand_bytes(16)
      iex> {ciphertext, tag} = SpeckEx.AEAD.encrypt("Hello", key, nonce, "aad")
      iex> tampered = <<0>> <> binary_part(ciphertext, 1, byte_size(ciphertext) - 1)
      iex> SpeckEx.AEAD.decrypt(tampered, tag, key, nonce, "aad")
      {:error, :authentication_failed}

  """
  @spec decrypt(binary, binary, binary, binary, binary, variant) ::
          {:ok, binary} | {:error, :authentication_failed}
  def decrypt(ciphertext, tag, key, nonce, aad, variant \\ :speck128_256)

  def decrypt(_, tag, _, _, _, _) when bit_size(tag) != 128, do: {:error, :authentication_failed}

  def decrypt(ciphertext, tag, <<key::binary-32>>, <<nonce::binary-16>>, aad, :speck128_256),
    do: Native.speck128_256_poly1305_decrypt(key, nonce, ciphertext, tag, aad) |> dec_result()

  def decrypt(ciphertext, tag, <<key::binary-24>>, <<nonce::binary-16>>, aad, :speck128_192),
    do: Native.speck128_192_poly1305_decrypt(key, nonce, ciphertext, tag, aad) |> dec_result()

  def decrypt(ciphertext, tag, <<key::binary-16>>, <<nonce::binary-16>>, aad, :speck128_128),
    do: Native.speck128_128_poly1305_decrypt(key, nonce, ciphertext, tag, aad) |> dec_result()

  def decrypt(ciphertext, tag, <<key::binary-16>>, <<nonce::binary-8>>, aad, :speck64_128),
    do: Native.speck64_128_poly1305_decrypt(key, nonce, ciphertext, tag, aad) |> dec_result()

  def decrypt(ciphertext, tag, <<key::binary-12>>, <<nonce::binary-8>>, aad, :speck64_96),
    do: Native.speck64_96_poly1305_decrypt(key, nonce, ciphertext, tag, aad) |> dec_result()

  def decrypt(ciphertext, tag, <<key::binary-8>>, <<nonce::binary-4>>, aad, :speck32_64),
    do: Native.speck32_64_poly1305_decrypt(key, nonce, ciphertext, tag, aad) |> dec_result()

  defp dec_result(:authentication_failed), do: {:error, :authentication_failed}
  defp dec_result(plaintext), do: {:ok, plaintext}
end
