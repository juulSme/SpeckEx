defmodule SpeckExTest do
  use ExUnit.Case
  doctest SpeckEx

  describe "CTR mode encryption/decryption" do
    test "encrypts and decrypts with default variant (speck128_256)" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World! This is a test message."

      ciphertext = SpeckEx.encrypt(plaintext, key, nonce)
      assert ciphertext != plaintext
      assert byte_size(ciphertext) == byte_size(plaintext)

      decrypted = SpeckEx.decrypt(ciphertext, key, nonce)
      assert decrypted == plaintext
    end

    test "encrypts and decrypts with speck128_128" do
      key = :crypto.strong_rand_bytes(16)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Testing with Speck128/128"

      ciphertext = SpeckEx.encrypt(plaintext, key, nonce, variant: :speck128_128)
      assert ciphertext != plaintext

      decrypted = SpeckEx.decrypt(ciphertext, key, nonce, variant: :speck128_128)
      assert decrypted == plaintext
    end

    test "encrypts and decrypts with speck64_128" do
      key = :crypto.strong_rand_bytes(16)
      nonce = :crypto.strong_rand_bytes(8)
      plaintext = "Testing with Speck64/128"

      ciphertext = SpeckEx.encrypt(plaintext, key, nonce, variant: :speck64_128)
      assert ciphertext != plaintext

      decrypted = SpeckEx.decrypt(ciphertext, key, nonce, variant: :speck64_128)
      assert decrypted == plaintext
    end

    test "handles empty plaintext" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = ""

      ciphertext = SpeckEx.encrypt(plaintext, key, nonce)
      assert ciphertext == ""

      decrypted = SpeckEx.decrypt(ciphertext, key, nonce)
      assert decrypted == plaintext
    end

    test "handles large plaintext" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = String.duplicate("A", 10000)

      ciphertext = SpeckEx.encrypt(plaintext, key, nonce)
      assert byte_size(ciphertext) == 10000

      decrypted = SpeckEx.decrypt(ciphertext, key, nonce)
      assert decrypted == plaintext
    end

    test "different nonces produce different ciphertexts" do
      key = :crypto.strong_rand_bytes(32)
      nonce1 = :crypto.strong_rand_bytes(16)
      nonce2 = :crypto.strong_rand_bytes(16)
      plaintext = "Same plaintext"

      ciphertext1 = SpeckEx.encrypt(plaintext, key, nonce1)
      ciphertext2 = SpeckEx.encrypt(plaintext, key, nonce2)

      assert ciphertext1 != ciphertext2
    end

    test "different keys produce different ciphertexts" do
      key1 = :crypto.strong_rand_bytes(32)
      key2 = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(16)
      plaintext = "Same plaintext"

      ciphertext1 = SpeckEx.encrypt(plaintext, key1, nonce)
      ciphertext2 = SpeckEx.encrypt(plaintext, key2, nonce)

      assert ciphertext1 != ciphertext2
    end

    test "fails with incorrect nonce size" do
      key = :crypto.strong_rand_bytes(16)
      # Wrong size for speck128_128
      nonce = :crypto.strong_rand_bytes(8)
      plaintext = "Test"

      assert_raise ArgumentError, ~r/nonce must be 128 bits/, fn ->
        SpeckEx.encrypt(plaintext, key, nonce)
      end
    end
  end
end

defmodule SpeckEx.BlockTest do
  use ExUnit.Case
  doctest SpeckEx.Block

  describe "speck32_64" do
    test "encrypts and decrypts" do
      key = :crypto.strong_rand_bytes(8)
      cipher = SpeckEx.Block.speck32_64_init!(key)
      plaintext = :crypto.strong_rand_bytes(4)

      ciphertext = SpeckEx.Block.speck32_64_encrypt!(plaintext, cipher)
      assert byte_size(ciphertext) == 4
      assert ciphertext != plaintext

      decrypted = SpeckEx.Block.speck32_64_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "speck48_72" do
    test "encrypts and decrypts" do
      key = :crypto.strong_rand_bytes(9)
      cipher = SpeckEx.Block.speck48_72_init!(key)
      plaintext = :crypto.strong_rand_bytes(6)

      ciphertext = SpeckEx.Block.speck48_72_encrypt!(plaintext, cipher)
      assert byte_size(ciphertext) == 6

      decrypted = SpeckEx.Block.speck48_72_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "speck48_96" do
    test "encrypts and decrypts" do
      key = :crypto.strong_rand_bytes(12)
      cipher = SpeckEx.Block.speck48_96_init!(key)
      plaintext = :crypto.strong_rand_bytes(6)

      ciphertext = SpeckEx.Block.speck48_96_encrypt!(plaintext, cipher)
      assert byte_size(ciphertext) == 6

      decrypted = SpeckEx.Block.speck48_96_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "speck64_96" do
    test "encrypts and decrypts" do
      key = :crypto.strong_rand_bytes(12)
      cipher = SpeckEx.Block.speck64_96_init!(key)
      plaintext = :crypto.strong_rand_bytes(8)

      ciphertext = SpeckEx.Block.speck64_96_encrypt!(plaintext, cipher)
      assert byte_size(ciphertext) == 8

      decrypted = SpeckEx.Block.speck64_96_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "speck64_128" do
    test "encrypts and decrypts" do
      key = :crypto.strong_rand_bytes(16)
      cipher = SpeckEx.Block.speck64_128_init!(key)
      plaintext = :crypto.strong_rand_bytes(8)

      ciphertext = SpeckEx.Block.speck64_128_encrypt!(plaintext, cipher)
      assert byte_size(ciphertext) == 8

      decrypted = SpeckEx.Block.speck64_128_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "speck96_96" do
    test "encrypts and decrypts" do
      key = :crypto.strong_rand_bytes(12)
      cipher = SpeckEx.Block.speck96_96_init!(key)
      plaintext = :crypto.strong_rand_bytes(12)

      ciphertext = SpeckEx.Block.speck96_96_encrypt!(plaintext, cipher)
      assert byte_size(ciphertext) == 12

      decrypted = SpeckEx.Block.speck96_96_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "speck96_144" do
    test "encrypts and decrypts" do
      key = :crypto.strong_rand_bytes(18)
      cipher = SpeckEx.Block.speck96_144_init!(key)
      plaintext = :crypto.strong_rand_bytes(12)

      ciphertext = SpeckEx.Block.speck96_144_encrypt!(plaintext, cipher)
      assert byte_size(ciphertext) == 12

      decrypted = SpeckEx.Block.speck96_144_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "speck128_128" do
    test "encrypts and decrypts" do
      key = :crypto.strong_rand_bytes(16)
      cipher = SpeckEx.Block.speck128_128_init!(key)
      plaintext = :crypto.strong_rand_bytes(16)

      ciphertext = SpeckEx.Block.speck128_128_encrypt!(plaintext, cipher)
      assert byte_size(ciphertext) == 16
      assert ciphertext != plaintext

      decrypted = SpeckEx.Block.speck128_128_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "speck128_192" do
    test "encrypts and decrypts" do
      key = :crypto.strong_rand_bytes(24)
      cipher = SpeckEx.Block.speck128_192_init!(key)
      plaintext = :crypto.strong_rand_bytes(16)

      ciphertext = SpeckEx.Block.speck128_192_encrypt!(plaintext, cipher)
      assert byte_size(ciphertext) == 16

      decrypted = SpeckEx.Block.speck128_192_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "speck128_256" do
    test "encrypts and decrypts" do
      key = :crypto.strong_rand_bytes(32)
      cipher = SpeckEx.Block.speck128_256_init!(key)
      plaintext = :crypto.strong_rand_bytes(16)

      ciphertext = SpeckEx.Block.speck128_256_encrypt!(plaintext, cipher)
      assert byte_size(ciphertext) == 16

      decrypted = SpeckEx.Block.speck128_256_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "error handling" do
    test "fails with invalid key length" do
      assert_raise FunctionClauseError, fn ->
        SpeckEx.Block.speck128_128_init!(:crypto.strong_rand_bytes(10))
      end
    end

    test "fails with invalid block size" do
      cipher = SpeckEx.Block.speck128_128_init!(:crypto.strong_rand_bytes(16))

      assert_raise FunctionClauseError, fn ->
        SpeckEx.Block.speck128_128_encrypt!(:crypto.strong_rand_bytes(8), cipher)
      end
    end
  end

  describe "deterministic encryption" do
    test "same input produces same output with same key" do
      key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
      plaintext = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>

      cipher1 = SpeckEx.Block.speck128_128_init!(key)
      cipher2 = SpeckEx.Block.speck128_128_init!(key)

      ciphertext1 = SpeckEx.Block.speck128_128_encrypt!(plaintext, cipher1)
      ciphertext2 = SpeckEx.Block.speck128_128_encrypt!(plaintext, cipher2)

      assert ciphertext1 == ciphertext2
    end

    test "different keys produce different outputs" do
      key1 = :crypto.strong_rand_bytes(16)
      key2 = :crypto.strong_rand_bytes(16)
      plaintext = :crypto.strong_rand_bytes(16)

      cipher1 = SpeckEx.Block.speck128_128_init!(key1)
      cipher2 = SpeckEx.Block.speck128_128_init!(key2)

      ciphertext1 = SpeckEx.Block.speck128_128_encrypt!(plaintext, cipher1)
      ciphertext2 = SpeckEx.Block.speck128_128_encrypt!(plaintext, cipher2)

      assert ciphertext1 != ciphertext2
    end
  end

  describe "test vectors - speck32/64" do
    test "official test vector 1" do
      # Key: 1918 1110 0908 0100
      key = <<0x19, 0x18, 0x11, 0x10, 0x09, 0x08, 0x01, 0x00>>
      # Plaintext: 6574 694c
      plaintext = <<0x65, 0x74, 0x69, 0x4C>>
      # Expected ciphertext: a868 42f2
      expected = <<0xA8, 0x68, 0x42, 0xF2>>

      cipher = SpeckEx.Block.speck32_64_init!(key)
      ciphertext = SpeckEx.Block.speck32_64_encrypt!(plaintext, cipher)
      assert ciphertext == expected

      decrypted = SpeckEx.Block.speck32_64_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "test vectors - speck48/72" do
    test "official test vector 1" do
      # Key: 121110 0a0908 020100
      key = <<0x12, 0x11, 0x10, 0x0A, 0x09, 0x08, 0x02, 0x01, 0x00>>
      # Plaintext: 20796c 6c6172
      plaintext = <<0x20, 0x79, 0x6C, 0x6C, 0x61, 0x72>>
      # Expected ciphertext: c049a5385adc
      expected = <<0xC0, 0x49, 0xA5, 0x38, 0x5A, 0xDC>>

      cipher = SpeckEx.Block.speck48_72_init!(key)
      ciphertext = SpeckEx.Block.speck48_72_encrypt!(plaintext, cipher)
      assert ciphertext == expected

      decrypted = SpeckEx.Block.speck48_72_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "test vectors - speck48/96" do
    test "official test vector 1" do
      # Key: 1a1918 121110 0a0908 020100
      key = <<0x1A, 0x19, 0x18, 0x12, 0x11, 0x10, 0x0A, 0x09, 0x08, 0x02, 0x01, 0x00>>
      # Plaintext: 6d2073 696874
      plaintext = <<0x6D, 0x20, 0x73, 0x69, 0x68, 0x74>>
      # Expected ciphertext: 735e10b6445d
      expected = <<0x73, 0x5E, 0x10, 0xB6, 0x44, 0x5D>>

      cipher = SpeckEx.Block.speck48_96_init!(key)
      ciphertext = SpeckEx.Block.speck48_96_encrypt!(plaintext, cipher)
      assert ciphertext == expected

      decrypted = SpeckEx.Block.speck48_96_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "test vectors - speck64/96" do
    test "official test vector 1" do
      # Key: 13121110 0b0a0908 03020100
      key = <<0x13, 0x12, 0x11, 0x10, 0x0B, 0x0A, 0x09, 0x08, 0x03, 0x02, 0x01, 0x00>>
      # Plaintext: 74614620 736e6165
      plaintext = <<0x74, 0x61, 0x46, 0x20, 0x73, 0x6E, 0x61, 0x65>>
      # Expected ciphertext: 9f7952ec4175946c
      expected = <<0x9F, 0x79, 0x52, 0xEC, 0x41, 0x75, 0x94, 0x6C>>

      cipher = SpeckEx.Block.speck64_96_init!(key)
      ciphertext = SpeckEx.Block.speck64_96_encrypt!(plaintext, cipher)
      assert ciphertext == expected

      decrypted = SpeckEx.Block.speck64_96_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "test vectors - speck64/128" do
    test "official test vector 1" do
      # Key: 1b1a1918 13121110 0b0a0908 03020100
      key =
        <<0x1B, 0x1A, 0x19, 0x18, 0x13, 0x12, 0x11, 0x10, 0x0B, 0x0A, 0x09, 0x08, 0x03, 0x02,
          0x01, 0x00>>

      # Plaintext: 3b726574 7475432d
      plaintext = <<0x3B, 0x72, 0x65, 0x74, 0x74, 0x75, 0x43, 0x2D>>
      # Expected ciphertext: 8c6fa548454e028b
      expected = <<0x8C, 0x6F, 0xA5, 0x48, 0x45, 0x4E, 0x02, 0x8B>>

      cipher = SpeckEx.Block.speck64_128_init!(key)
      ciphertext = SpeckEx.Block.speck64_128_encrypt!(plaintext, cipher)
      assert ciphertext == expected

      decrypted = SpeckEx.Block.speck64_128_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "test vectors - speck96/96" do
    test "official test vector 1" do
      # Key: 0d0c0b0a0908050403020100
      key = <<0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00>>
      # Plaintext: 65776f68202c656761737520 ("ow, ho egasu ")
      plaintext = <<0x65, 0x77, 0x6F, 0x68, 0x20, 0x2C, 0x65, 0x67, 0x61, 0x73, 0x75, 0x20>>
      # Expected: 9e4d09ab717862bdde8f79aa
      expected = <<0x9E, 0x4D, 0x09, 0xAB, 0x71, 0x78, 0x62, 0xBD, 0xDE, 0x8F, 0x79, 0xAA>>

      cipher = SpeckEx.Block.speck96_96_init!(key)
      ciphertext = SpeckEx.Block.speck96_96_encrypt!(plaintext, cipher)
      assert ciphertext == expected

      decrypted = SpeckEx.Block.speck96_96_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "test vectors - speck96/144" do
    test "official test vector 1" do
      # Key: 1514131211100d0c0b0a0908050403020100
      key =
        <<0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x05, 0x04,
          0x03, 0x02, 0x01, 0x00>>

      # Plaintext: 656d6974206e69202c726576 ("emit ni ,rev")
      plaintext = <<0x65, 0x6D, 0x69, 0x74, 0x20, 0x6E, 0x69, 0x20, 0x2C, 0x72, 0x65, 0x76>>
      # Expected: 2bf31072228a7ae440252ee6
      expected =
        <<0x2B, 0xF3, 0x10, 0x72, 0x22, 0x8A, 0x7A, 0xE4, 0x40, 0x25, 0x2E, 0xE6>>

      cipher = SpeckEx.Block.speck96_144_init!(key)
      ciphertext = SpeckEx.Block.speck96_144_encrypt!(plaintext, cipher)
      assert ciphertext == expected

      decrypted = SpeckEx.Block.speck96_144_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "test vectors - speck128/128" do
    test "official test vector 1" do
      # Key: 0f0e0d0c0b0a0908 0706050403020100
      key =
        <<0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
          0x01, 0x00>>

      # Plaintext: 6c61766975716520 7469206564616d20
      plaintext =
        <<0x6C, 0x61, 0x76, 0x69, 0x75, 0x71, 0x65, 0x20, 0x74, 0x69, 0x20, 0x65, 0x64, 0x61,
          0x6D, 0x20>>

      # Expected ciphertext: a65d985179783265 7860fedf5c570d18
      expected =
        <<0xA6, 0x5D, 0x98, 0x51, 0x79, 0x78, 0x32, 0x65, 0x78, 0x60, 0xFE, 0xDF, 0x5C, 0x57,
          0x0D, 0x18>>

      cipher = SpeckEx.Block.speck128_128_init!(key)
      ciphertext = SpeckEx.Block.speck128_128_encrypt!(plaintext, cipher)
      assert ciphertext == expected

      decrypted = SpeckEx.Block.speck128_128_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "test vectors - speck128/192" do
    test "official test vector 1" do
      # Key: 17161514131211100f0e0d0c0b0a09080706050403020100
      key =
        <<0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A,
          0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00>>

      # Plaintext: 7261482066656968 43206f7420746e65
      plaintext =
        <<0x72, 0x61, 0x48, 0x20, 0x66, 0x65, 0x69, 0x68, 0x43, 0x20, 0x6F, 0x74, 0x20, 0x74,
          0x6E, 0x65>>

      # Expected ciphertext: 1be4cf3a13135566f9bc185de03c1886
      expected =
        <<0x1B, 0xE4, 0xCF, 0x3A, 0x13, 0x13, 0x55, 0x66, 0xF9, 0xBC, 0x18, 0x5D, 0xE0, 0x3C,
          0x18, 0x86>>

      cipher = SpeckEx.Block.speck128_192_init!(key)
      ciphertext = SpeckEx.Block.speck128_192_encrypt!(plaintext, cipher)
      assert ciphertext == expected

      decrypted = SpeckEx.Block.speck128_192_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end

  describe "test vectors - speck128/256" do
    test "official test vector 1" do
      # Key: 1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
      key =
        <<0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12,
          0x11, 0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04,
          0x03, 0x02, 0x01, 0x00>>

      # Plaintext: 65736f6874206e49 202e72656e6f6f70
      plaintext =
        <<0x65, 0x73, 0x6F, 0x68, 0x74, 0x20, 0x6E, 0x49, 0x20, 0x2E, 0x72, 0x65, 0x6E, 0x6F,
          0x6F, 0x70>>

      # Expected ciphertext: 4109010405c0f53e4eeeb48d9c188f43
      expected =
        <<0x41, 0x09, 0x01, 0x04, 0x05, 0xC0, 0xF5, 0x3E, 0x4E, 0xEE, 0xB4, 0x8D, 0x9C, 0x18,
          0x8F, 0x43>>

      cipher = SpeckEx.Block.speck128_256_init!(key)
      ciphertext = SpeckEx.Block.speck128_256_encrypt!(plaintext, cipher)
      assert ciphertext == expected

      decrypted = SpeckEx.Block.speck128_256_decrypt!(ciphertext, cipher)
      assert decrypted == plaintext
    end
  end
end
