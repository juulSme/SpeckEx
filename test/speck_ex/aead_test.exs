defmodule SpeckEx.AEADTest do
  use ExUnit.Case, async: true
  doctest SpeckEx.AEAD

  alias SpeckEx.CTR
  alias SpeckEx.AEAD

  describe "encrypt/5 and decrypt/6" do
    test "successful round-trip with default variant (speck128_256)" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World!"
      aad = "user_id:12345"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad)

      assert byte_size(ciphertext) == byte_size(plaintext)
      assert byte_size(tag) == 16
      assert ciphertext != plaintext

      assert {:ok, ^plaintext} = AEAD.decrypt(ciphertext, tag, key, nonce, aad)
    end

    test "successful round-trip with empty plaintext" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = ""
      aad = "metadata"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad)

      assert ciphertext == ""
      assert byte_size(tag) == 16

      assert {:ok, ^plaintext} = AEAD.decrypt(ciphertext, tag, key, nonce, aad)
    end

    test "successful round-trip with empty AAD" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Secret message"
      aad = ""

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad)

      assert {:ok, ^plaintext} = AEAD.decrypt(ciphertext, tag, key, nonce, aad)
    end

    test "successful round-trip with large plaintext" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = :crypto.strong_rand_bytes(10_000)
      aad = "large_data"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad)

      assert byte_size(ciphertext) == 10_000
      assert {:ok, ^plaintext} = AEAD.decrypt(ciphertext, tag, key, nonce, aad)
    end

    test "round-trips a megabyte with large associated data" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = :binary.copy(<<42>>, 1_048_576)
      aad = :binary.copy(<<7>>, 1_048_576)

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad)

      assert {:ok, ^plaintext} = AEAD.decrypt(ciphertext, tag, key, nonce, aad)

      assert {:error, :authentication_failed} =
               AEAD.decrypt(ciphertext, tag, key, nonce, aad <> <<0>>)
    end
  end

  describe "authentication failures" do
    test "fails with tampered ciphertext" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World!"
      aad = "metadata"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad)

      # Tamper with ciphertext
      tampered_ciphertext = ciphertext <> <<0>>

      assert {:error, :authentication_failed} =
               AEAD.decrypt(tampered_ciphertext, tag, key, nonce, aad)
    end

    test "fails with tampered tag" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World!"
      aad = "metadata"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad)

      # Tamper with tag
      <<first_byte, rest::binary>> = tag
      tampered_tag = <<255 - first_byte, rest::binary>>

      assert {:error, :authentication_failed} =
               AEAD.decrypt(ciphertext, tampered_tag, key, nonce, aad)
    end

    test "fails with wrong key" do
      key = :crypto.strong_rand_bytes(32)
      wrong_key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World!"
      aad = "metadata"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad)

      assert {:error, :authentication_failed} =
               AEAD.decrypt(ciphertext, tag, wrong_key, nonce, aad)
    end

    test "fails with wrong nonce" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      wrong_nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World!"
      aad = "metadata"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad)

      assert {:error, :authentication_failed} =
               AEAD.decrypt(ciphertext, tag, key, wrong_nonce, aad)
    end

    test "fails with wrong AAD" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World!"
      aad = "metadata"
      wrong_aad = "wrong_metadata"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad)

      assert {:error, :authentication_failed} =
               AEAD.decrypt(ciphertext, tag, key, nonce, wrong_aad)
    end

    test "fails with tampered AAD (empty vs non-empty)" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World!"
      aad = "metadata"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad)

      # Try with empty AAD
      assert {:error, :authentication_failed} =
               AEAD.decrypt(ciphertext, tag, key, nonce, "")
    end
  end

  describe "all supported variants" do
    test "round-trips small and large messages and associated data" do
      variants = [
        {:speck32_64, 8, 4},
        {:speck64_96, 12, 8},
        {:speck64_128, 16, 8},
        {:speck128_128, 16, 16},
        {:speck128_192, 24, 16},
        {:speck128_256, 32, 16}
      ]

      for {variant, key_size, nonce_size} <- variants,
          {message_size, aad_size} <- [{16_383, 0}, {16_384, 0}, {0, 16_384}, {8_192, 8_192}] do
        key = :crypto.strong_rand_bytes(key_size)
        nonce = :crypto.strong_rand_bytes(nonce_size)
        plaintext = :binary.copy(<<42>>, message_size)
        aad = :binary.copy(<<7>>, aad_size)
        {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad, variant)

        assert {:ok, ^plaintext} = AEAD.decrypt(ciphertext, tag, key, nonce, aad, variant)

        assert {:error, :authentication_failed} =
                 AEAD.decrypt(ciphertext, tag, key, nonce, aad <> <<0>>, variant)
      end
    end

    test "speck32_64 variant" do
      key = :crypto.strong_rand_bytes(8)
      nonce = :crypto.strong_rand_bytes(4)
      plaintext = "Test message"
      aad = "aad"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad, :speck32_64)

      assert byte_size(tag) == 16

      assert {:ok, ^plaintext} =
               AEAD.decrypt(ciphertext, tag, key, nonce, aad, :speck32_64)
    end

    test "speck64_96 variant" do
      key = :crypto.strong_rand_bytes(12)
      nonce = :crypto.strong_rand_bytes(8)
      plaintext = "Test message"
      aad = "aad"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad, :speck64_96)

      assert byte_size(tag) == 16

      assert {:ok, ^plaintext} =
               AEAD.decrypt(ciphertext, tag, key, nonce, aad, :speck64_96)
    end

    test "speck64_128 variant" do
      key = :crypto.strong_rand_bytes(16)
      nonce = :crypto.strong_rand_bytes(8)
      plaintext = "Test message"
      aad = "aad"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad, :speck64_128)

      assert byte_size(tag) == 16

      assert {:ok, ^plaintext} =
               AEAD.decrypt(ciphertext, tag, key, nonce, aad, :speck64_128)
    end

    test "speck128_128 variant" do
      key = :crypto.strong_rand_bytes(16)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Test message"
      aad = "aad"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad, :speck128_128)

      assert byte_size(tag) == 16

      assert {:ok, ^plaintext} =
               AEAD.decrypt(ciphertext, tag, key, nonce, aad, :speck128_128)
    end

    test "speck128_192 variant" do
      key = :crypto.strong_rand_bytes(24)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Test message"
      aad = "aad"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad, :speck128_192)

      assert byte_size(tag) == 16

      assert {:ok, ^plaintext} =
               AEAD.decrypt(ciphertext, tag, key, nonce, aad, :speck128_192)
    end

    test "speck128_256 variant (explicit)" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Test message"
      aad = "aad"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad, :speck128_256)

      assert byte_size(tag) == 16

      assert {:ok, ^plaintext} =
               AEAD.decrypt(ciphertext, tag, key, nonce, aad, :speck128_256)
    end
  end

  describe "error handling" do
    test "raises on invalid key size" do
      # Wrong size
      key = :crypto.strong_rand_bytes(31)
      nonce = :crypto.strong_rand_bytes(16)

      assert_raise FunctionClauseError, fn ->
        AEAD.encrypt("test", key, nonce, "")
      end
    end

    test "raises on invalid nonce size" do
      key = :crypto.strong_rand_bytes(32)
      # Wrong size
      nonce = :crypto.strong_rand_bytes(15)

      assert_raise FunctionClauseError, fn ->
        AEAD.encrypt("test", key, nonce, "")
      end
    end

    test "returns error when tag is wrong length" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      ciphertext = "test"
      # Wrong size
      tag = :crypto.strong_rand_bytes(15)

      assert {:error, :authentication_failed} = AEAD.decrypt(ciphertext, tag, key, nonce, "")
    end

    test "raises on unknown variant" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)

      assert_raise FunctionClauseError, fn ->
        AEAD.encrypt("test", key, nonce, "", :speck64_128)
      end
    end
  end

  describe "property: ciphertext is different from plaintext (except empty)" do
    test "ciphertext differs from plaintext for non-trivial inputs" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "This is a test message that should be encrypted"
      aad = "metadata"

      {ciphertext, _tag} = AEAD.encrypt(plaintext, key, nonce, aad)

      assert ciphertext != plaintext
      assert byte_size(ciphertext) == byte_size(plaintext)
    end
  end

  describe "property: different nonces produce different ciphertexts" do
    test "same plaintext with different nonces produces different ciphertexts" do
      key = :crypto.strong_rand_bytes(32)
      nonce1 = :crypto.strong_rand_bytes(16)
      nonce2 = :crypto.strong_rand_bytes(16)
      plaintext = "Same message"
      aad = "aad"

      {ciphertext1, tag1} = AEAD.encrypt(plaintext, key, nonce1, aad)
      {ciphertext2, tag2} = AEAD.encrypt(plaintext, key, nonce2, aad)

      assert ciphertext1 != ciphertext2
      assert tag1 != tag2
    end
  end

  defp pad16(binary) do
    length = byte_size(binary)
    # Aligned inputs, including empty binaries, need no padding.
    padding_bytes = rem(16 - rem(length, 16), 16)
    {length, :binary.copy(<<0>>, padding_bytes)}
  end

  describe "poly1305 tag verification with :crypto" do
    test "tags match :crypto for empty, partial, and aligned inputs" do
      key = :binary.copy(<<1>>, 32)
      nonce = :binary.copy(<<2>>, 16)
      poly_key = CTR.crypt(<<0::256>>, key, nonce)

      for plaintext_size <- [0, 1, 15, 16, 17, 32], aad_size <- [0, 1, 15, 16, 17, 32] do
        plaintext = :binary.copy(<<3>>, plaintext_size)
        aad = :binary.copy(<<4>>, aad_size)
        {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad)
        {aad_len, aad_pad} = pad16(aad)
        {ct_len, ct_pad} = pad16(ciphertext)

        mac_data =
          aad <> aad_pad <> ciphertext <> ct_pad <> <<aad_len::little-64, ct_len::little-64>>

        expected_tag = :crypto.mac(:poly1305, poly_key, mac_data)
        assert tag == expected_tag
        assert {:ok, ^plaintext} = AEAD.decrypt(ciphertext, expected_tag, key, nonce, aad)
      end
    end

    test "preserves key-dependent encryption and authentication across variants and schedulers" do
      variants = [
        {:speck32_64, 8, 4},
        {:speck64_96, 12, 8},
        {:speck64_128, 16, 8},
        {:speck128_128, 16, 16},
        {:speck128_192, 24, 16},
        {:speck128_256, 32, 16}
      ]

      for {variant, key_size, nonce_size} <- variants, message_size <- [37, 16_385] do
        key = :binary.copy(<<1>>, key_size)
        other_key = :binary.copy(<<2>>, key_size)
        nonce = :binary.copy(<<3>>, nonce_size)
        plaintext = :binary.copy(<<4>>, message_size)
        aad = "metadata"

        {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad, variant)
        {other_ciphertext, _other_tag} = AEAD.encrypt(plaintext, other_key, nonce, aad, variant)

        <<poly_key::binary-32, expected_ciphertext::binary>> =
          CTR.crypt(<<0::256>> <> plaintext, key, nonce, variant)

        {aad_len, aad_pad} = pad16(aad)
        {ct_len, ct_pad} = pad16(ciphertext)

        mac_data =
          aad <> aad_pad <> ciphertext <> ct_pad <> <<aad_len::little-64, ct_len::little-64>>

        expected_tag = :crypto.mac(:poly1305, poly_key, mac_data)
        zero_key_tag = :crypto.mac(:poly1305, <<0::256>>, mac_data)

        assert ciphertext == expected_ciphertext
        assert ciphertext != other_ciphertext
        assert tag == expected_tag

        assert {:ok, ^plaintext} =
                 AEAD.decrypt(ciphertext, expected_tag, key, nonce, aad, variant)

        assert {:error, :authentication_failed} =
                 AEAD.decrypt(ciphertext, tag, other_key, nonce, aad, variant)

        assert {:error, :authentication_failed} =
                 AEAD.decrypt(ciphertext, zero_key_tag, key, nonce, aad, variant)

        assert {ciphertext, tag} == AEAD.encrypt(plaintext, key, nonce, aad, variant)
        assert key == :binary.copy(<<1>>, key_size)
        assert other_key == :binary.copy(<<2>>, key_size)
      end
    end

    test "tag matches :crypto.poly1305 for default variant" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Test message for Poly1305 verification"
      aad = "additional data"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad)

      # Derive Poly1305 key from Speck cipher with zero counter
      poly_key = SpeckEx.CTR.crypt(<<0::256>>, key, nonce, :speck128_256)

      {aad_len, aad_pad} = pad16(aad)
      {ct_len, ct_pad} = pad16(ciphertext)

      mac_data =
        aad <>
          aad_pad <>
          ciphertext <>
          ct_pad <>
          <<aad_len::little-64, ct_len::little-64>>

      # Verify tag matches
      expected_tag = :crypto.mac(:poly1305, poly_key, mac_data)

      assert tag == expected_tag
    end

    test "tag matches :crypto.poly1305 for speck128_128 variant" do
      key = :crypto.strong_rand_bytes(16)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Another test"
      aad = "more aad"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad, :speck128_128)

      # Derive Poly1305 key
      poly_key = SpeckEx.CTR.crypt(<<0::256>>, key, nonce, :speck128_128)

      # Construct MAC input
      {aad_len, aad_pad} = pad16(aad)
      {ct_len, ct_pad} = pad16(ciphertext)

      mac_data =
        aad <>
          aad_pad <>
          ciphertext <>
          ct_pad <>
          <<aad_len::little-64, ct_len::little-64>>

      expected_tag = :crypto.mac(:poly1305, poly_key, mac_data)

      assert tag == expected_tag
    end

    test "tag matches :crypto.poly1305 with empty AAD" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Message without AAD"
      aad = ""

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad)

      poly_key = SpeckEx.CTR.crypt(<<0::256>>, key, nonce, :speck128_256)

      {ct_len, ct_pad} = pad16(ciphertext)

      mac_data = ciphertext <> ct_pad <> <<0::little-64, ct_len::little-64>>
      expected_tag = :crypto.mac(:poly1305, poly_key, mac_data)

      assert tag == expected_tag
    end
  end

  test "matches CTR" do
    key = :crypto.strong_rand_bytes(32)
    nonce = :crypto.strong_rand_bytes(16)
    plaintext = "my incredibly interesting and secret message"
    aad = ""
    {aead_ct, _} = AEAD.encrypt(plaintext, key, nonce, aad)
    <<_::256, ctr_ct::binary>> = CTR.crypt(<<0::256>> <> plaintext, key, nonce)
    assert aead_ct == ctr_ct
  end
end
