defmodule SpeckEx do
  @moduledoc """
  A high-performance Elixir library for the Speck block cipher, powered by Rust NIFs.
  Provides Speck in three modes: high-level CTR mode encryption, authenticated encryption in the form of Speck-Poly1305 and the primitive block cipher.

  This module provides a clean, high-level API that attempts to protect lib users from missteps. Lower-level implementations without these guardrails can be found in `SpeckEx.Block` (primitive block cipher), `SpeckEx.CTR` (counter mode) and `SpeckEx.AEAD` (authenticated encryption using Speck-Poly1305). You should not use these submodules directly unless you know what you are doing.

  > #### Experimental code {: .warning}
  >
  > This package is in an experimental state. It has not been audited or reviewed, and its backing Rust packages haven't either. The AEAD-mode in particular, combining Speck and Poly1305, is running dangerously close to "rolling your own encryption". Use at your own risk.

  ## Supported Variants

  The default variant for all operations is `:speck128_256` (128-bit block, 256-bit key).

  CTR and AEAD modes support variants with 128-bit block sizes:

  - `:speck128_128` - 128-bit block, 128-bit key
  - `:speck128_192` - 128-bit block, 192-bit key
  - `:speck128_256` - 128-bit block, 256-bit key (default)

  ## Usage

      # CTR mode encryption
      iex> key = :crypto.strong_rand_bytes(32)
      iex> {nonce, ciphertext} = SpeckEx.crypt("Hello, World!", key)
      iex> {_nonce, plaintext} = SpeckEx.crypt(ciphertext, key, nonce: nonce)
      iex> plaintext
      "Hello, World!"

      # AEAD mode (authenticated encryption)
      iex> key = :crypto.strong_rand_bytes(32)
      iex> {nonce, ciphertext, tag} = SpeckEx.aead_encrypt("Secret", key, aad: "metadata")
      iex> SpeckEx.aead_decrypt(ciphertext, tag, key, nonce, aad: "metadata")
      {:ok, "Secret"}

  ## Security guidelines

  > #### TL;DR {: .info}
  >
  > Use the main `SpeckEx` module, it securely generates nonces for you and returns them. Don't encrypt more than 64GiB with the same nonce, and cycle the key after 4 billion messages. Avoid the `SpeckEx.CTR`, `SpeckEx.AEAD` and `SpeckEx.Block` modules unless you know what you are doing.

  Nonce generation is a particularly tricky business, about which `m::crypto` is not particularly helpful or informative.
  The problem: CTR modes, CTR-based modes like AES-GCM, and equivalent streaming ciphers like ChaCha20 and ChaCha20-Poly1305 are all critically vulnerable to nonce reuse, as are Speck CTR and AEAD modes. Nonce reuse leads to complete confidentiality failure, exposing all messages encrypted with the reused nonce.

  What is less well known is that it is not just the initial input nonce that must be unique.
  In CTR mode, the nonce is treated like a big counter (e.g., 128-bit) that increments for every encrypted block—
  *and the counter values generated during encryption must also be unique (under the same key)*.
  In ChaCha20, the first 64 bits of its 128-bit nonce are treated as a counter; each "block" is 512 bits.
  Tests illustrating all of this can be found [on Github](https://github.com/juulSme/SpeckEx/blob/main/test/speck_ex/endianness_test.exs).

  This implies that if you encrypt 1000 blocks per message, your input nonces must not just be unique,
  but must be spaced at least 1000 increments apart to avoid collision.
  In general, it is common practice to reserve 32 bits for the counter portion.
  With 128-bit block ciphers, this allows encrypting up to 2^32 * 16 bytes (64 GiB) per nonce (in theory).

  That's why schemes like AES-GCM require a 96-bit nonce, even though AES uses a 128-bit block.
  The remaining 32 bits are reserved for the internal counter (initialized to a specific value).
  (GCM mode is actually more complicated, but this captures the key idea.)

  Which brings us to `m::crypto`. For `:crypto.crypto_one_time_aead/6`, it requires 96-bit nonces for AES-GCM and ChaCha20-Poly1305. This provides a somewhat safe default: users only worry about uniqueness of the input nonce; the library manages the internal counter space.

  For CTR modes and plain ChaCha20 via `:crypto.crypto_one_time/5`, however, no such guardrail exists. A full block-sized nonce is required, and it's left to the user to realize that counter space is needed *and how to partition it*.
  This is further complicated by inconsistency: AES-CTR in OTP treats the entire nonce as a big-endian counter (incrementing the rightmost byte first), while ChaCha20 treats only the first 8 bytes as a little-endian 64-bit counter (incrementing the leftmost byte first). That means the counter space for AES-CTR must be *appended* while the counter space for ChaCha20 must be *prepended* to (for example) a 96-bits nonce.

  To round off this rather confusing state of affairs, generating the input nonce itself is left to the user, who hopefully uses `:crypto.strong_rand_bytes/1` and is aware of the birthday problem (don't encrypt too much data under the same key with random nonces). Alternatively, users may implement a deterministic counter mechanism, which is notoriously hazardous in distributed systems - exactly the kind Erlang/Elixir deployments are encouraged to be.

  ### So how about SpeckEx?

  SpeckEx uses big endian CTR/AEAD modes that treat the entire nonce as a counter, equivalent to AES-CTR in OTP.
  It tries to protect the lib user in the same way as `:crypto.crypto_one_time_aead/6` does; by requiring 96-bits nonces and managing the 32-bits counter space internally.
  However, unlike OTP it also does so for the unauthenticated CTR mode.
  Another layer of protection is offered by the fact that smaller block size variants of the cipher (32 and 64 bits) that *could* be used in CTR/AEAD modes but *shouldn't* are not accessible through the main module.
  Finally, no nonce is required as input by default; it is generated securely internally and returned.
  The returned nonce does have to be provided for decryption, naturally.
  Because only 128-bits ciphers are used, there's a clear recommendation to avoid birthday bounds: don't encrypt more than 64 GiB with the same nonce, and cycle your key after 4 billion messages.

  It is strongly recommended that users stick to the main module.
  The `SpeckEx.CTR` and `SpeckEx.AEAD` modules offer access to all supported modes (32, 64 and 128 bits block sizes) and have no guardrails; they require a nonce that matches the block size and that's it.
  You only need them if you want to use a small block-size cipher or want to divide the nonce and counter space in some other way than the main module.
  Needless to say: you are on your own and do so at your own risk.
  You should be exceedingly careful, you can't use random nonces for the small ciphers and you should be aware of the birthday bounds of your chosen block size (you can only securely encrypt 4 * 2^16 = 256KB with the 32-bits cipher, for example, insofar as a 32-bits cipher is secure in the first place).
  """
  alias SpeckEx.{AEAD, Block, CTR}

  @typedoc """
  Speck variants supported by AEAD mode (128-bit block sizes).
  Naming: `speck<block_size>_<key_size>`, sizes in bits.
  """
  @type aead_variant :: :speck128_128 | :speck128_192 | :speck128_256

  @typedoc """
  Speck variants supported by CTR mode (128-bit block sizes).
  Naming: `speck<block_size>_<key_size>`, sizes in bits.
  """
  @type ctr_variant :: :speck128_128 | :speck128_192 | :speck128_256

  @typedoc """
  Parameters for a variant; `{block_size, key_size}` in bits.
  """
  @type variant_parameters :: {pos_integer(), pos_integer()}

  @typedoc "Options for CTR mode."
  @type ctr_opt :: {:variant, ctr_variant()} | {:nonce, <<_::96>>}

  @typedoc "Options for AEAD mode."
  @type aead_opt :: {:variant, aead_variant()} | {:nonce, <<_::96>>} | {:aad, binary()}

  @typedoc "Key for speck128_128, speck128_192 and speck128_256"
  @type key :: <<_::128>> | <<_::192>> | <<_::256>>

  # CTR Mode Functions

  @doc """
  En/decrypts data using CTR mode.

  There is no difference between the two in CTR mode.

  ## Parameters
  - `plaintext` - The data to en/decrypt (binary of any length)
  - `key` - The encryption key (length must match the variant's key size)
  - `opts` - Keyword list of options:
    - `:nonce` - The nonce (12 bytes, auto-generated if not provided, required for decryption)
    - `:variant` - The Speck variant to use (default: `:speck128_256`)

  ## Returns
  A tuple `{nonce, ciphertext}` or `{nonce, plaintext}` where:
  - `nonce` is the 12-byte nonce (auto-generated or provided)
  - `ciphertext`/`plaintext` is the encrypted or decrypted data

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {nonce, ciphertext} = SpeckEx.crypt("Hello, World!", key)
      iex> byte_size(nonce)
      12
      iex> {_nonce, plaintext} = SpeckEx.crypt(ciphertext, key, nonce: nonce)
      iex> plaintext
      "Hello, World!"

      iex> key = :crypto.strong_rand_bytes(32)
      iex> nonce = :crypto.strong_rand_bytes(12)
      iex> {^nonce, ciphertext} = SpeckEx.crypt("Hello, World!", key, nonce: nonce, variant: :speck128_256)
      iex> {^nonce, plaintext} = SpeckEx.crypt(ciphertext, key, nonce: nonce, variant: :speck128_256)
      iex> plaintext
      "Hello, World!"

  """
  @spec crypt(binary, key(), [ctr_opt()]) :: {<<_::96>>, binary}
  def crypt(data, key, opts \\ []) do
    variant = opts[:variant] || :speck128_256
    nonce = opts[:nonce] || :crypto.strong_rand_bytes(12)
    {nonce, do_ctr(data, key, nonce, variant)}
  end

  defp do_ctr(data, key, nonce, variant)
       when variant in [:speck128_128, :speck128_192, :speck128_256] do
    CTR.crypt(data, key, nonce <> <<0::32>>, variant)
  end

  # AEAD Mode Functions

  @doc """
  Encrypts plaintext and computes an authentication tag using AEAD mode.

  Returns a tuple `{nonce, ciphertext, tag}` where:
  - `nonce` is the 12-byte nonce (auto-generated or provided)
  - `ciphertext` is the encrypted data (same length as plaintext)
  - `tag` is a 16-byte Poly1305 authentication tag

  ## Parameters

  - `plaintext` - The data to encrypt (binary, any length)
  - `key` - The encryption key (size depends on variant)
  - `opts` - Keyword list of options:
    - `:nonce` - The nonce (12 bytes, auto-generated if not provided)
    - `:aad` - Associated authenticated data (binary, any length, defaults to "")
    - `:variant` - The Speck variant to use (default: `:speck128_256`)

  ## Returns

  A tuple `{nonce, ciphertext, tag}`.

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {nonce, ciphertext, tag} = SpeckEx.aead_encrypt("Secret", key, aad: "metadata")
      iex> byte_size(nonce) == 12 and is_binary(ciphertext) and byte_size(tag) == 16
      true

  """
  @spec aead_encrypt(binary, key(), [aead_opt()]) :: {<<_::96>>, binary, <<_::128>>}
  def aead_encrypt(plaintext, key, opts \\ []) do
    variant = opts[:variant] || :speck128_256
    nonce = opts[:nonce] || :crypto.strong_rand_bytes(12)
    aad = opts[:aad] || ""
    {ciphertext, tag} = do_aead_enc(plaintext, key, nonce, aad, variant)
    {nonce, ciphertext, tag}
  end

  defp do_aead_enc(plaintext, key, nonce, aad, variant)
       when variant in [:speck128_128, :speck128_192, :speck128_256] do
    AEAD.encrypt(plaintext, key, nonce <> <<0::32>>, aad, variant)
  end

  @doc """
  Verifies the authentication tag and decrypts the ciphertext using AEAD mode.

  Returns `{:ok, plaintext}` if authentication succeeds, or
  `{:error, :authentication_failed}` if the tag is invalid.

  ## Parameters

  - `ciphertext` - The encrypted data (binary, any length)
  - `tag` - The 16-byte Poly1305 authentication tag
  - `key` - The encryption key (size depends on variant)
  - `nonce` - The 12-byte nonce (must match the one from encryption)
  - `opts` - Keyword list of options:
    - `:aad` - Associated authenticated data (must match encryption, defaults to "")
    - `:variant` - The Speck variant to use (default: `:speck128_256`)

  ## Returns

  `{:ok, plaintext}` or `{:error, :authentication_failed}`.

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {nonce, ciphertext, tag} = SpeckEx.aead_encrypt("Secret", key, aad: "metadata")
      iex> SpeckEx.aead_decrypt(ciphertext, tag, key, nonce, aad: "metadata")
      {:ok, "Secret"}

  """
  @spec aead_decrypt(binary, <<_::128>>, key(), <<_::96>>, [aead_opt()]) ::
          {:ok, binary} | {:error, :authentication_failed}
  def aead_decrypt(ciphertext, tag, key, nonce, opts \\ []) do
    variant = opts[:variant] || :speck128_256
    aad = opts[:aad] || ""
    do_aead_dec(ciphertext, tag, key, nonce, aad, variant)
  end

  defp do_aead_dec(ciphertext, tag, key, nonce, aad, variant)
       when variant in [:speck128_128, :speck128_192, :speck128_256] do
    AEAD.decrypt(ciphertext, tag, key, nonce <> <<0::32>>, aad, variant)
  end

  @variants %{
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
  }

  @doc """
  Returns a map of all supported Speck variants with their block and key sizes.

  ## Returns
  A map where keys are variant atoms and values are tuples of {block_size_bits, key_size_bits}.
  """
  @spec variants() :: %{Block.variant() => variant_parameters()}
  def variants, do: @variants
end
