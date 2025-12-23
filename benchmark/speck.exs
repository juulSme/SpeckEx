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

# 1000 blocks
plaintext = :crypto.strong_rand_bytes(16 * 1000)
nonce = :crypto.strong_rand_bytes(16)

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
  "AES 128/256 CTR 1K blocks enc" => [
    fn -> :crypto.crypto_one_time(:aes_256_ctr, key256, nonce, plaintext, true) end,
    tasks: tasks
  ],
  "Speck 128/256 CTR 1K blocks enc" => [
    fn -> SpeckEx.CTR.crypt(plaintext, key256, nonce) end,
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
  "AES 128/256 AEAD 1K blocks enc" => [
    fn -> :crypto.crypto_one_time_aead(:aes_256_gcm, key256, nonce, plaintext, "", true) end,
    tasks: tasks
  ],
  "Speck 128/256 AEAD 1K blocks enc" => [
    fn -> SpeckEx.AEAD.encrypt(plaintext, key256, nonce, "") end,
    tasks: tasks
  ]
}
|> Benchmark.bench_many()
|> Benchmark.format_results()
|> IO.puts()
