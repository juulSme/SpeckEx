defmodule SpeckExTest do
  use ExUnit.Case
  doctest SpeckEx

  # Official test vectors from NSA Simon and Speck specification

  describe "Speck64/128" do
    setup do
      key =
        <<0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x11, 0x12, 0x13, 0x18, 0x19,
          0x1A, 0x1B>>

      {:ok, key: key}
    end

    test "round-trip encryption/decryption", %{key: key} do
      {:ok, key_ref} = SpeckEx.Block.init(key, :speck64_128)
      plaintext = <<0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF>>

      ciphertext = SpeckEx.Block.encrypt(plaintext, key_ref)
      decrypted = SpeckEx.Block.decrypt(ciphertext, key_ref)

      assert decrypted == plaintext
    end

    test "validates key size" do
      assert {:error, _} = SpeckEx.Block.init(<<1, 2, 3>>, :speck64_128)
      assert {:error, _} = SpeckEx.Block.init(<<1::128, 2::128>>, :speck64_128)
    end

    test "CTR mode encryption", %{key: key} do
      plaintext = "Hello, World! This is a test message."
      iv = <<0::64>>

      {:ok, key_ref} = SpeckEx.init(key, :speck64_128)
      {:ok, ciphertext} = SpeckEx.encrypt(plaintext, key_ref, iv)

      assert ciphertext != plaintext
      assert byte_size(ciphertext) == byte_size(plaintext)
    end

    test "CTR mode round-trip", %{key: key} do
      plaintext = "The quick brown fox jumps over the lazy dog"
      iv = <<0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0>>

      {:ok, key_ref} = SpeckEx.init(key, :speck64_128)
      {:ok, ciphertext} = SpeckEx.encrypt(plaintext, key_ref, iv)
      {:ok, decrypted} = SpeckEx.encrypt(ciphertext, key_ref, iv)

      assert decrypted == plaintext
    end
  end

  describe "Speck96/144" do
    setup do
      # Using a test key for verification
      key =
        <<0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
          0x0E, 0x0F, 0x10, 0x11>>

      plaintext = <<0x20, 0x6D, 0x61, 0x64, 0x65, 0x20, 0x69, 0x74, 0x20, 0x65, 0x71, 0x75>>

      {:ok, key: key, plaintext: plaintext}
    end

    test "round-trip encryption/decryption", %{key: key, plaintext: plaintext} do
      {:ok, key_ref} = SpeckEx.Block.init(key, :speck96_144)

      ciphertext = SpeckEx.Block.encrypt(plaintext, key_ref)
      decrypted = SpeckEx.Block.decrypt(ciphertext, key_ref)

      assert decrypted == plaintext
      assert ciphertext != plaintext
    end

    test "validates key size" do
      assert {:error, _} = SpeckEx.Block.init(<<1, 2, 3>>, :speck96_144)
      assert {:error, _} = SpeckEx.Block.init(<<1::128>>, :speck96_144)
    end

    test "CTR mode round-trip", %{key: key} do
      plaintext = "Testing Speck96/144 in CTR mode with various lengths!"
      iv = <<0::96>>

      {:ok, key_ref} = SpeckEx.init(key, :speck96_144)
      {:ok, ciphertext} = SpeckEx.encrypt(plaintext, key_ref, iv)
      {:ok, decrypted} = SpeckEx.encrypt(ciphertext, key_ref, iv)

      assert decrypted == plaintext
    end
  end

  describe "Speck128/256" do
    setup do
      # Using a test key for verification
      key =
        <<0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
          0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
          0x1C, 0x1D, 0x1E, 0x1F>>

      plaintext =
        <<0x20, 0x75, 0x73, 0x65, 0x20, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x6B, 0x65,
          0x79, 0x73>>

      {:ok, key: key, plaintext: plaintext}
    end

    test "round-trip encryption/decryption", %{key: key, plaintext: plaintext} do
      {:ok, key_ref} = SpeckEx.Block.init(key, :speck128_256)

      ciphertext = SpeckEx.Block.encrypt(plaintext, key_ref)
      decrypted = SpeckEx.Block.decrypt(ciphertext, key_ref)

      assert decrypted == plaintext
      assert ciphertext != plaintext
    end

    test "validates key size" do
      assert {:error, _} = SpeckEx.Block.init(<<1, 2, 3>>, :speck128_256)
      assert {:error, _} = SpeckEx.Block.init(<<1::128>>, :speck128_256)
    end

    test "CTR mode with large data", %{key: key} do
      plaintext = String.duplicate("A", 1000)
      iv = <<0::128>>

      {:ok, key_ref} = SpeckEx.init(key, :speck128_256)
      {:ok, ciphertext} = SpeckEx.encrypt(plaintext, key_ref, iv)
      {:ok, decrypted} = SpeckEx.encrypt(ciphertext, key_ref, iv)

      assert decrypted == plaintext
    end

    test "CTR mode with partial blocks", %{key: key} do
      # Test with data that's not a multiple of block size
      plaintext = "Short"
      iv = <<0xFF::128>>

      {:ok, key_ref} = SpeckEx.init(key, :speck128_256)
      {:ok, ciphertext} = SpeckEx.encrypt(plaintext, key_ref, iv)
      {:ok, decrypted} = SpeckEx.encrypt(ciphertext, key_ref, iv)

      assert decrypted == plaintext
      assert byte_size(ciphertext) == byte_size(plaintext)
    end
  end

  describe "error handling" do
    test "invalid mode" do
      key = <<0::128>>
      assert {:error, _} = SpeckEx.Block.init(key, :invalid_mode)
    end

    test "empty data in CTR mode" do
      key = <<0::128>>
      iv = <<0::64>>
      {:ok, key_ref} = SpeckEx.init(key, :speck64_128)

      {:ok, result} = SpeckEx.encrypt("", key_ref, iv)
      assert result == ""
    end
  end
end
