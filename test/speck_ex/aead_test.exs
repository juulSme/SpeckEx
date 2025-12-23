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
  end

  describe "authentication failures" do
    test "fails with tampered ciphertext" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World!"
      aad = "metadata"

      {ciphertext, tag} = AEAD.encrypt(plaintext, key, nonce, aad)

      # Tamper with ciphertext
      tampered_ciphertext = :binary.part(ciphertext, 0, byte_size(ciphertext) - 1) <> <<0>>

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
      tampered_tag = :binary.part(tag, 0, 15) <> <<0>>

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
    bin_len = byte_size(binary)
    {bin_len, <<0::size(8 * (16 - rem(bin_len, 16)))>>}
  end

  describe "poly1305 tag verification with :crypto" do
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
