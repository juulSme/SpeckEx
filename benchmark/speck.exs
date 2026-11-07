alias SpeckEx.Block

tasks = 1

key128 = :crypto.strong_rand_bytes(16)
blowfish_e = :crypto.crypto_init(:blowfish_ecb, key128, true)
blowfish_d = :crypto.crypto_init(:blowfish_ecb, key128, false)
key256 = :crypto.strong_rand_bytes(32)
aes128_256_e = :crypto.crypto_init(:aes_256_ecb, key256, true)
aes128_256_d = :crypto.crypto_init(:aes_256_ecb, key256, false)
speck128_256 = key256 |> Block.init(:speck128_256)
speck96_144 = :crypto.strong_rand_bytes(18) |> Block.init(:speck96_144)
speck64_128 = key128 |> Block.init(:speck64_128)

block128 = :crypto.strong_rand_bytes(16)
block96 = :crypto.strong_rand_bytes(12)
block64 = :crypto.strong_rand_bytes(8)

nonce = :crypto.strong_rand_bytes(16)
data_below_limit = :crypto.strong_rand_bytes(16_383)
data_at_limit = :crypto.strong_rand_bytes(16_384)

%{
  "Speck 64/128 block enc" => [
    fn -> Block.encrypt(block64, speck64_128, :speck64_128) end,
    tasks: tasks
  ],
  "Speck 96/144 block enc" => [
    fn -> Block.encrypt(block96, speck96_144, :speck96_144) end,
    tasks: tasks
  ],
  "Speck 128/256 block enc" => [
    fn -> Block.encrypt(block128, speck128_256, :speck128_256) end,
    tasks: tasks
  ],
  "AES 128/256 block enc" => [
    fn -> :crypto.crypto_update(aes128_256_e, block128) end,
    tasks: tasks
  ],
  "Blowfish 64/128 block enc" => [
    fn -> :crypto.crypto_update(blowfish_e, block64) end,
    tasks: tasks
  ],
  "Speck 64/128 block dec" => [
    fn -> Block.decrypt(block64, speck64_128, :speck64_128) end,
    tasks: tasks
  ],
  "Speck 96/144 block dec" => [
    fn -> Block.decrypt(block96, speck96_144, :speck96_144) end,
    tasks: tasks
  ],
  "Speck 128/256 block dec" => [
    fn -> Block.decrypt(block128, speck128_256, :speck128_256) end,
    tasks: tasks
  ],
  "AES 128/256 block dec" => [
    fn -> :crypto.crypto_update(aes128_256_d, block128) end,
    tasks: tasks
  ],
  "Blowfish 64/128 block dec" => [
    fn -> :crypto.crypto_update(blowfish_d, block64) end,
    tasks: tasks
  ],
  "Speck 128/256 init + block enc" => [
    fn ->
      speck128_256 = key256 |> Block.init(:speck128_256)
      Block.encrypt(block128, speck128_256, :speck128_256)
    end,
    tasks: tasks
  ],
  "AES 128/256 init + block enc" => [
    fn -> :crypto.crypto_one_time(:aes_256_ecb, key256, block128, true) end,
    tasks: tasks
  ],
  "Blowfish 64/128 init + block enc" => [
    fn -> :crypto.crypto_one_time(:blowfish_ecb, key128, block64, true) end,
    tasks: tasks
  ],
  "AES 128/256 CTR enc 16384 bytes" => [
    fn -> :crypto.crypto_one_time(:aes_256_ctr, key256, nonce, data_at_limit, true) end,
    tasks: tasks
  ],
  "Speck 128/256 CTR enc 16383 bytes" => [
    fn -> SpeckEx.CTR.crypt(data_below_limit, key256, nonce) end,
    tasks: tasks
  ],
  "Speck 128/256 CTR enc 16384 bytes" => [
    fn -> SpeckEx.CTR.crypt(data_at_limit, key256, nonce) end,
    tasks: tasks
  ],
  "AES 128/256 AEAD enc 16384 bytes" => [
    fn -> :crypto.crypto_one_time_aead(:aes_256_gcm, key256, nonce, data_at_limit, "", true) end,
    tasks: tasks
  ],
  "Speck 128/256 AEAD enc 16383 bytes" => [
    fn -> SpeckEx.AEAD.encrypt(data_below_limit, key256, nonce, "") end,
    tasks: tasks
  ],
  "Speck 128/256 AEAD enc 16384 bytes" => [
    fn -> SpeckEx.AEAD.encrypt(data_at_limit, key256, nonce, "") end,
    tasks: tasks
  ],
  "AES 128/256 AEAD AAD 16384 bytes" => [
    fn -> :crypto.crypto_one_time_aead(:aes_256_gcm, key256, nonce, "", data_at_limit, true) end,
    tasks: tasks
  ],
  "Speck 128/256 AEAD AAD 16383 bytes" => [
    fn -> SpeckEx.AEAD.encrypt("", key256, nonce, data_below_limit) end,
    tasks: tasks
  ],
  "Speck 128/256 AEAD AAD 16384 bytes" => [
    fn -> SpeckEx.AEAD.encrypt("", key256, nonce, data_at_limit) end,
    tasks: tasks
  ]
}
|> Benchmark.bench_many()
|> Benchmark.format_results()
|> IO.puts()
