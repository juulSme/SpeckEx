alias SpeckEx.Block

key256 = :crypto.strong_rand_bytes(32)
aes128_256_e = :crypto.crypto_init(:aes_256_ecb, key256, true)
aes128_256_d = :crypto.crypto_init(:aes_256_ecb, key256, false)
speck128_256 = key256 |> Block.speck128_256_init!()
speck96_144 = :crypto.strong_rand_bytes(18) |> Block.speck96_144_init!()
speck64_128 = :crypto.strong_rand_bytes(16) |> Block.speck64_128_init!()

block128 = :crypto.strong_rand_bytes(16)
block96 = :crypto.strong_rand_bytes(12)
block64 = :crypto.strong_rand_bytes(8)

# 1000 blocks
plaintext = :crypto.strong_rand_bytes(16 * 1000)
iv = :crypto.strong_rand_bytes(16)

%{
  "Speck 64/128 block enc" => [
    fn -> Block.speck64_128_encrypt!(block64, speck64_128) end,
    tasks: 1
  ],
  "Speck 96/144 block enc" => [
    fn -> Block.speck96_144_encrypt!(block96, speck96_144) end,
    tasks: 1
  ],
  "Speck 128/256 block enc" => [
    fn -> Block.speck128_256_encrypt!(block128, speck128_256) end,
    tasks: 1
  ],
  "AES 128/256 block enc" => [fn -> :crypto.crypto_update(aes128_256_e, block128) end, tasks: 1],
  "Speck 64/128 block dec" => [
    fn -> Block.speck64_128_decrypt!(block64, speck64_128) end,
    tasks: 1
  ],
  "Speck 96/144 block dec" => [
    fn -> Block.speck96_144_decrypt!(block96, speck96_144) end,
    tasks: 1
  ],
  "Speck 128/256 block dec" => [
    fn -> Block.speck128_256_decrypt!(block128, speck128_256) end,
    tasks: 1
  ],
  "AES 128/256 block dec" => [fn -> :crypto.crypto_update(aes128_256_d, block128) end, tasks: 1],
  "AES 128/256 CTR enc" => [
    fn -> :crypto.crypto_one_time(:aes_256_ctr, key256, iv, plaintext, true) end,
    tasks: 1
  ],
  "Speck 128/256 CTR enc" => [
    fn -> SpeckEx.encrypt(plaintext, key256, iv) end,
    tasks: 1
  ]
}
|> Benchmark.bench_many()
|> Benchmark.format_results()
|> IO.puts()
