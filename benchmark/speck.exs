{:ok, key256} = :crypto.strong_rand_bytes(32) |> SpeckEx.init(:speck128_256)
{:ok, key144} = :crypto.strong_rand_bytes(18) |> SpeckEx.init(:speck96_144)
{:ok, key128} = :crypto.strong_rand_bytes(16) |> SpeckEx.init(:speck64_128)

block128 = :crypto.strong_rand_bytes(16)
block96 = :crypto.strong_rand_bytes(12)
block64 = :crypto.strong_rand_bytes(8)

plaintext = "What a great day for benchmarking. Truly magnificent. We shall type even more words."

%{
  "Speck 64/128 CTR" => [fn ->  SpeckEx.encrypt(plaintext, key128, <<0::64>>) end, tasks: 1],
  "Speck 64/128 block" => [fn ->  SpeckEx.Block.encrypt(block64, key128) end, tasks: 1],
  "Speck 96/144 CTR" => [fn ->  SpeckEx.encrypt(plaintext, key144, <<0::96>>) end, tasks: 1],
  "Speck 96/144 block" => [fn ->  SpeckEx.Block.encrypt(block96, key144) end, tasks: 1],
  "Speck 128/256 CTR" => [fn ->  SpeckEx.encrypt(plaintext, key256, <<0::128>>) end, tasks: 1],
  "Speck 128/256 block" => [fn ->  SpeckEx.Block.encrypt(block128, key256) end, tasks: 1],
}
|> Benchmark.bench_many()
|> Benchmark.format_results()
|> IO.puts()
