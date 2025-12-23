defmodule SpeckEx.CTRTest do
  use ExUnit.Case, async: true
  doctest SpeckEx.CTR

  alias SpeckEx.CTR

  describe "encrypt/4 and decrypt/4" do
    test "successful round-trip with default variant (speck128_256)" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World!"

      ciphertext = CTR.crypt(plaintext, key, nonce)

      assert byte_size(ciphertext) == byte_size(plaintext)
      assert ciphertext != plaintext

      assert ^plaintext = CTR.crypt(ciphertext, key, nonce)
    end

    test "successful round-trip with empty plaintext" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = ""

      ciphertext = CTR.crypt(plaintext, key, nonce)

      assert ciphertext == ""

      assert ^plaintext = CTR.crypt(ciphertext, key, nonce)
    end

    test "successful round-trip with large plaintext" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = :crypto.strong_rand_bytes(10_000)

      ciphertext = CTR.crypt(plaintext, key, nonce)

      assert byte_size(ciphertext) == 10_000
      assert ^plaintext = CTR.crypt(ciphertext, key, nonce)
    end

    test "encryption is deterministic with same key and nonce" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World!"

      ciphertext1 = CTR.crypt(plaintext, key, nonce)
      ciphertext2 = CTR.crypt(plaintext, key, nonce)

      assert ciphertext1 == ciphertext2
    end

    test "different IVs produce different ciphertexts" do
      key = :crypto.strong_rand_bytes(32)
      iv1 = :crypto.strong_rand_bytes(16)
      iv2 = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World!"

      ciphertext1 = CTR.crypt(plaintext, key, iv1)
      ciphertext2 = CTR.crypt(plaintext, key, iv2)

      assert ciphertext1 != ciphertext2
    end

    test "different keys produce different ciphertexts" do
      key1 = :crypto.strong_rand_bytes(32)
      key2 = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World!"

      ciphertext1 = CTR.crypt(plaintext, key1, nonce)
      ciphertext2 = CTR.crypt(plaintext, key2, nonce)

      assert ciphertext1 != ciphertext2
    end

    test "ciphertext differs from plaintext for non-empty data" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "A" <> String.duplicate("B", 100)

      ciphertext = CTR.crypt(plaintext, key, nonce)

      assert ciphertext != plaintext
    end
  end

  describe "all supported variants" do
    test "speck32_64 variant" do
      key = :crypto.strong_rand_bytes(8)
      nonce = :crypto.strong_rand_bytes(4)
      plaintext = "Test message for speck32_64"

      ciphertext = CTR.crypt(plaintext, key, nonce, :speck32_64)

      assert byte_size(ciphertext) == byte_size(plaintext)
      assert ^plaintext = CTR.crypt(ciphertext, key, nonce, :speck32_64)
    end

    test "speck64_96 variant" do
      key = :crypto.strong_rand_bytes(12)
      nonce = :crypto.strong_rand_bytes(8)
      plaintext = "Test message for speck64_96"

      ciphertext = CTR.crypt(plaintext, key, nonce, :speck64_96)

      assert byte_size(ciphertext) == byte_size(plaintext)
      assert ^plaintext = CTR.crypt(ciphertext, key, nonce, :speck64_96)
    end

    test "speck64_128 variant" do
      key = :crypto.strong_rand_bytes(16)
      nonce = :crypto.strong_rand_bytes(8)
      plaintext = "Test message for speck64_128"

      ciphertext = CTR.crypt(plaintext, key, nonce, :speck64_128)

      assert byte_size(ciphertext) == byte_size(plaintext)
      assert ^plaintext = CTR.crypt(ciphertext, key, nonce, :speck64_128)
    end

    test "speck128_128 variant" do
      key = :crypto.strong_rand_bytes(16)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Test message for speck128_128"

      ciphertext = CTR.crypt(plaintext, key, nonce, :speck128_128)

      assert byte_size(ciphertext) == byte_size(plaintext)
      assert ^plaintext = CTR.crypt(ciphertext, key, nonce, :speck128_128)
    end

    test "speck128_192 variant" do
      key = :crypto.strong_rand_bytes(24)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Test message for speck128_192"

      ciphertext = CTR.crypt(plaintext, key, nonce, :speck128_192)

      assert byte_size(ciphertext) == byte_size(plaintext)
      assert ^plaintext = CTR.crypt(ciphertext, key, nonce, :speck128_192)
    end

    test "speck128_256 variant (explicit)" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Test message for speck128_256"

      ciphertext = CTR.crypt(plaintext, key, nonce, :speck128_256)

      assert byte_size(ciphertext) == byte_size(plaintext)
      assert ^plaintext = CTR.crypt(ciphertext, key, nonce, :speck128_256)
    end
  end

  describe "security properties" do
    test "same plaintext with different IVs produces different ciphertexts" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = "Sensitive data"

      results =
        for _ <- 1..10 do
          nonce = :crypto.strong_rand_bytes(16)
          CTR.crypt(plaintext, key, nonce)
        end

      # All ciphertexts should be unique
      assert Enum.uniq(results) == results
    end

    test "flipping a bit in ciphertext produces different plaintext" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World!"

      ciphertext = CTR.crypt(plaintext, key, nonce)

      # Flip the first bit
      <<first_byte, rest::binary>> = ciphertext
      tampered_ciphertext = <<Bitwise.bxor(first_byte, 1), rest::binary>>

      tampered_plaintext = CTR.crypt(tampered_ciphertext, key, nonce)

      assert tampered_plaintext != plaintext
    end

    test "large data encryption produces unique ciphertext" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)

      # Create plaintext with repeating pattern
      plaintext = String.duplicate("AAAABBBBCCCCDDDD", 1000)

      ciphertext = CTR.crypt(plaintext, key, nonce)

      # Ciphertext should not have obvious repeating patterns
      # Check that not all blocks are identical
      block_size = 16

      blocks =
        for i <- 0..(div(byte_size(ciphertext), block_size) - 1) do
          :binary.part(ciphertext, i * block_size, block_size)
        end

      unique_blocks = Enum.uniq(blocks)
      assert length(unique_blocks) > 100
    end
  end

  describe "error handling" do
    test "raises on invalid key size for default variant" do
      # Wrong size for speck128_256 (expects 32 bytes)
      key = :crypto.strong_rand_bytes(31)
      nonce = :crypto.strong_rand_bytes(16)

      assert_raise FunctionClauseError, fn ->
        CTR.crypt("test", key, nonce)
      end
    end

    test "raises on invalid nonce size for default variant" do
      key = :crypto.strong_rand_bytes(32)
      # Wrong size for speck128_256 (expects 16 bytes)
      nonce = :crypto.strong_rand_bytes(15)

      assert_raise FunctionClauseError, fn ->
        CTR.crypt("test", key, nonce)
      end
    end

    test "raises on mismatched key size for speck64_96" do
      # Wrong size for speck64_96 (expects 12 bytes)
      key = :crypto.strong_rand_bytes(16)
      nonce = :crypto.strong_rand_bytes(8)

      assert_raise FunctionClauseError, fn ->
        CTR.crypt("test", key, nonce, :speck64_96)
      end
    end

    test "raises on mismatched nonce size for speck128_128" do
      key = :crypto.strong_rand_bytes(16)
      # Wrong size for speck128_128 (expects 16 bytes)
      nonce = :crypto.strong_rand_bytes(8)

      assert_raise FunctionClauseError, fn ->
        CTR.crypt("test", key, nonce, :speck128_128)
      end
    end
  end

  describe "CTR mode properties" do
    test "encryption and decryption use the same operation" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      data = "Test data"

      # Encrypt
      encrypted_once = CTR.crypt(data, key, nonce)

      # "Encrypt" the ciphertext (should decrypt it)
      decrypted = CTR.crypt(encrypted_once, key, nonce)

      assert decrypted == data
    end

    test "partial decryption is possible" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World! This is a longer message."

      ciphertext = CTR.crypt(plaintext, key, nonce)

      # Decrypt only first 13 bytes
      partial_ciphertext = :binary.part(ciphertext, 0, 13)
      partial_plaintext = CTR.crypt(partial_ciphertext, key, nonce)

      assert partial_plaintext == "Hello, World!"
    end
  end
end
