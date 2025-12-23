defmodule SpeckEx.EndiannessTest do
  use ExUnit.Case, async: true
  alias SpeckEx.AEAD
  alias SpeckEx.CTR

  describe ":crypto AES-CTR" do
    test "is big endian" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = <<0::256>>

      nonce1 = <<0::128>>
      <<_b1::128, b2::128>> = :crypto.crypto_one_time(:aes_256_ctr, key, nonce1, plaintext, true)

      nonce2 = <<0::127, 1::1>>

      assert <<^b2::128, _b3::128>> =
               :crypto.crypto_one_time(:aes_256_ctr, key, nonce2, plaintext, true)
    end

    test "rolls over all bytes" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = <<0::256>>

      nonce1 = <<255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255>>
      <<_b1::128, b2::128>> = :crypto.crypto_one_time(:aes_256_ctr, key, nonce1, plaintext, true)

      nonce2 = <<0::128>>

      assert <<^b2::128, _b3::128>> =
               :crypto.crypto_one_time(:aes_256_ctr, key, nonce2, plaintext, true)
    end
  end

  describe ":crypto chacha20" do
    test "is little endian" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = <<0::1024>>

      nonce1 = <<0::128>>

      <<_b1::512, b2::512>> =
        :crypto.crypto_one_time(:chacha20, key, nonce1, plaintext, true)

      nonce2 = <<0::7, 1::1, 0::120>>

      assert <<^b2::512, _b3::512>> =
               :crypto.crypto_one_time(:chacha20, key, nonce2, plaintext, true)
    end

    test "rolls over first 8 bytes only" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = <<0::1024>>

      nonce1 = <<255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255>>
      <<_b1::512, b2::512>> = :crypto.crypto_one_time(:chacha20, key, nonce1, plaintext, true)

      nonce2 = <<0::64, 255, 255, 255, 255, 255, 255, 255, 255>>

      assert <<^b2::512, _b3::512>> =
               :crypto.crypto_one_time(:chacha20, key, nonce2, plaintext, true)
    end
  end

  describe "Speck CTR mode" do
    test "is big endian" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = <<0::256>>

      nonce1 = <<0::128>>
      <<_b1::128, b2::128>> = CTR.crypt(plaintext, key, nonce1)

      nonce2 = <<0::127, 1::1>>
      assert <<^b2::128, _b3::128>> = CTR.crypt(plaintext, key, nonce2)
    end

    test "rolls over all bytes" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = <<0::256>>

      nonce1 = <<255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255>>
      <<_b1::128, b2::128>> = CTR.crypt(plaintext, key, nonce1)

      nonce2 = <<0::128>>
      assert <<^b2::128, _b3::128>> = CTR.crypt(plaintext, key, nonce2)
    end
  end

  describe "Speck AEAD mode" do
    test "is big endian" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = <<0::256>>

      nonce1 = <<0::128>>
      {<<_b1::128, b2::128>>, <<_tag::128>>} = AEAD.encrypt(plaintext, key, nonce1, "")

      nonce2 = <<0::127, 1::1>>
      assert {<<^b2::128, _b3::128>>, <<_tag::128>>} = AEAD.encrypt(plaintext, key, nonce2, "")
    end

    test "rolls over all bytes" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = <<0::256>>

      nonce1 = <<255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255>>
      {<<_b1::128, b2::128>>, <<_tag::128>>} = AEAD.encrypt(plaintext, key, nonce1, "")

      nonce2 = <<0::128>>
      assert {<<^b2::128, _b3::128>>, <<_tag::128>>} = AEAD.encrypt(plaintext, key, nonce2, "")
    end
  end
end
