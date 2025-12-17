defmodule SpeckExTest do
  use ExUnit.Case
  doctest SpeckEx

  describe "CTR mode encryption/decryption" do
    test "encrypts and decrypts with default variant (speck128_256)" do
      key = :crypto.strong_rand_bytes(32)
      iv = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World! This is a test message."

      ciphertext = SpeckEx.encrypt(plaintext, key, iv)
      assert ciphertext != plaintext
      assert byte_size(ciphertext) == byte_size(plaintext)

      decrypted = SpeckEx.decrypt(ciphertext, key, iv)
      assert decrypted == plaintext
    end

    test "encrypts and decrypts with speck128_128" do
      key = :crypto.strong_rand_bytes(16)
      iv = :crypto.strong_rand_bytes(16)
      plaintext = "Testing with Speck128/128"

      ciphertext = SpeckEx.encrypt(plaintext, key, iv, :speck128_128)
      assert ciphertext != plaintext

      decrypted = SpeckEx.decrypt(ciphertext, key, iv, :speck128_128)
      assert decrypted == plaintext
    end

    test "encrypts and decrypts with speck64_128" do
      key = :crypto.strong_rand_bytes(16)
      iv = :crypto.strong_rand_bytes(8)
      plaintext = "Testing with Speck64/128"

      ciphertext = SpeckEx.encrypt(plaintext, key, iv, :speck64_128)
      assert ciphertext != plaintext

      decrypted = SpeckEx.decrypt(ciphertext, key, iv, :speck64_128)
      assert decrypted == plaintext
    end

    test "handles empty plaintext" do
      key = :crypto.strong_rand_bytes(32)
      iv = :crypto.strong_rand_bytes(16)
      plaintext = ""

      ciphertext = SpeckEx.encrypt(plaintext, key, iv)
      assert ciphertext == ""

      decrypted = SpeckEx.decrypt(ciphertext, key, iv)
      assert decrypted == plaintext
    end

    test "handles large plaintext" do
      key = :crypto.strong_rand_bytes(32)
      iv = :crypto.strong_rand_bytes(16)
      plaintext = String.duplicate("A", 10000)

      ciphertext = SpeckEx.encrypt(plaintext, key, iv)
      assert byte_size(ciphertext) == 10000

      decrypted = SpeckEx.decrypt(ciphertext, key, iv)
      assert decrypted == plaintext
    end

    test "different ivs produce different ciphertexts" do
      key = :crypto.strong_rand_bytes(32)
      iv1 = :crypto.strong_rand_bytes(16)
      iv2 = :crypto.strong_rand_bytes(16)
      plaintext = "Same plaintext"

      ciphertext1 = SpeckEx.encrypt(plaintext, key, iv1)
      ciphertext2 = SpeckEx.encrypt(plaintext, key, iv2)

      assert ciphertext1 != ciphertext2
    end

    test "different keys produce different ciphertexts" do
      key1 = :crypto.strong_rand_bytes(32)
      key2 = :crypto.strong_rand_bytes(32)
      iv = :crypto.strong_rand_bytes(16)
      plaintext = "Same plaintext"

      ciphertext1 = SpeckEx.encrypt(plaintext, key1, iv)
      ciphertext2 = SpeckEx.encrypt(plaintext, key2, iv)

      assert ciphertext1 != ciphertext2
    end

    test "fails with incorrect iv size" do
      key = :crypto.strong_rand_bytes(16)
      # Wrong size for speck128_128
      iv = :crypto.strong_rand_bytes(8)
      plaintext = "Test"

      assert_raise FunctionClauseError, fn -> SpeckEx.encrypt(plaintext, key, iv) end
    end
  end
end
