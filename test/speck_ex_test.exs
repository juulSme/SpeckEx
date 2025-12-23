defmodule SpeckExTest do
  use ExUnit.Case
  doctest SpeckEx

  describe "CTR mode encryption/decryption" do
    test "encrypts and decrypts with default variant (speck128_256)" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = "Hello, World! This is a test message."

      {nonce, ciphertext} = SpeckEx.crypt(plaintext, key)
      assert ciphertext != plaintext
      assert byte_size(ciphertext) == byte_size(plaintext)
      assert byte_size(nonce) == 12

      {_nonce, decrypted} = SpeckEx.crypt(ciphertext, key, nonce: nonce)
      assert decrypted == plaintext
    end

    test "encrypts and decrypts with speck128_128" do
      key = :crypto.strong_rand_bytes(16)
      plaintext = "Testing with Speck128/128"

      {nonce, ciphertext} = SpeckEx.crypt(plaintext, key, variant: :speck128_128)
      assert ciphertext != plaintext
      assert byte_size(nonce) == 12

      {_nonce, decrypted} = SpeckEx.crypt(ciphertext, key, nonce: nonce, variant: :speck128_128)
      assert decrypted == plaintext
    end

    test "encrypts and decrypts with manual nonce" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(12)
      plaintext = "Testing with manual nonce"

      {^nonce, ciphertext} = SpeckEx.crypt(plaintext, key, nonce: nonce)
      assert ciphertext != plaintext

      {^nonce, decrypted} = SpeckEx.crypt(ciphertext, key, nonce: nonce)
      assert decrypted == plaintext
    end

    test "handles empty plaintext" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = ""

      {nonce, ciphertext} = SpeckEx.crypt(plaintext, key)
      assert ciphertext == ""

      {_nonce, decrypted} = SpeckEx.crypt(ciphertext, key, nonce: nonce)
      assert decrypted == plaintext
    end

    test "handles large plaintext" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = String.duplicate("A", 10000)

      {nonce, ciphertext} = SpeckEx.crypt(plaintext, key)
      assert byte_size(ciphertext) == 10000

      {_nonce, decrypted} = SpeckEx.crypt(ciphertext, key, nonce: nonce)
      assert decrypted == plaintext
    end

    test "auto-generated nonces are unique" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = "Same plaintext"

      {nonce1, ciphertext1} = SpeckEx.crypt(plaintext, key)
      {nonce2, ciphertext2} = SpeckEx.crypt(plaintext, key)

      assert nonce1 != nonce2
      assert ciphertext1 != ciphertext2
    end

    test "different keys produce different ciphertexts" do
      key1 = :crypto.strong_rand_bytes(32)
      key2 = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(12)
      plaintext = "Same plaintext"

      {^nonce, ciphertext1} = SpeckEx.crypt(plaintext, key1, nonce: nonce)
      {^nonce, ciphertext2} = SpeckEx.crypt(plaintext, key2, nonce: nonce)

      assert ciphertext1 != ciphertext2
    end

    test "fails with incorrect nonce size" do
      key = :crypto.strong_rand_bytes(16)
      # Wrong size - expects 12 bytes
      nonce = :crypto.strong_rand_bytes(8)
      plaintext = "Test"

      assert_raise FunctionClauseError, fn -> SpeckEx.crypt(plaintext, key, nonce: nonce) end
    end
  end

  describe "AEAD mode encryption/decryption" do
    test "encrypts and decrypts with default variant (speck128_256)" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = "Secret message"
      aad = "user_id:12345"

      {nonce, ciphertext, tag} = SpeckEx.aead_encrypt(plaintext, key, aad: aad)

      assert byte_size(ciphertext) == byte_size(plaintext)
      assert byte_size(tag) == 16
      assert byte_size(nonce) == 12
      assert ciphertext != plaintext

      assert {:ok, ^plaintext} = SpeckEx.aead_decrypt(ciphertext, tag, key, nonce, aad: aad)
    end

    test "encrypts and decrypts with speck128_128" do
      key = :crypto.strong_rand_bytes(16)
      plaintext = "Testing AEAD with Speck128/128"
      aad = "metadata"

      {nonce, ciphertext, tag} =
        SpeckEx.aead_encrypt(plaintext, key, variant: :speck128_128, aad: aad)

      assert {:ok, ^plaintext} =
               SpeckEx.aead_decrypt(ciphertext, tag, key, nonce, variant: :speck128_128, aad: aad)
    end

    test "auto-generated nonces are unique" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = "Secret message"
      aad = "metadata"

      {nonce1, ciphertext1, tag1} = SpeckEx.aead_encrypt(plaintext, key, aad: aad)
      {nonce2, ciphertext2, tag2} = SpeckEx.aead_encrypt(plaintext, key, aad: aad)

      assert nonce1 != nonce2
      assert ciphertext1 != ciphertext2
      # Tags should also differ since ciphertext differs
      assert tag1 != tag2
    end

    test "authentication fails with tampered ciphertext" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = "Secret message"
      aad = "metadata"

      {nonce, ciphertext, tag} = SpeckEx.aead_encrypt(plaintext, key, aad: aad)

      # Tamper with ciphertext
      tampered = :binary.part(ciphertext, 0, byte_size(ciphertext) - 1) <> <<0>>

      assert {:error, :authentication_failed} =
               SpeckEx.aead_decrypt(tampered, tag, key, nonce, aad: aad)
    end

    test "authentication fails with wrong AAD" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = "Secret message"
      aad = "metadata"

      {nonce, ciphertext, tag} = SpeckEx.aead_encrypt(plaintext, key, aad: aad)

      assert {:error, :authentication_failed} =
               SpeckEx.aead_decrypt(ciphertext, tag, key, nonce, aad: "wrong_metadata")
    end

    test "handles empty plaintext" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = ""
      aad = "metadata"

      {nonce, ciphertext, tag} = SpeckEx.aead_encrypt(plaintext, key, aad: aad)

      assert ciphertext == ""
      assert byte_size(tag) == 16
      assert byte_size(nonce) == 12

      assert {:ok, ^plaintext} = SpeckEx.aead_decrypt(ciphertext, tag, key, nonce, aad: aad)
    end

    test "encrypts with manual nonce" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(12)
      plaintext = "Secret message"
      aad = "metadata"

      {^nonce, ciphertext, tag} = SpeckEx.aead_encrypt(plaintext, key, nonce: nonce, aad: aad)

      assert {:ok, ^plaintext} = SpeckEx.aead_decrypt(ciphertext, tag, key, nonce, aad: aad)
    end
  end
end
