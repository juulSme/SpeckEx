key256 = :crypto.strong_rand_bytes(32) |> SpeckEx.speck128_256_init!()
key144 = :crypto.strong_rand_bytes(18) |> SpeckEx.speck96_144_init!()
key128 = :crypto.strong_rand_bytes(16) |> SpeckEx.speck64_128_init!()

block128 = :crypto.strong_rand_bytes(16)
block96 = :crypto.strong_rand_bytes(12)
block64 = :crypto.strong_rand_bytes(8)

%{
  "Speck 64/128 block" => [fn ->  SpeckEx.speck64_128_encrypt!(block64, key128) end, tasks: 1],
  "Speck 96/144 block" => [fn ->  SpeckEx.speck96_144_encrypt!(block96, key144) end, tasks: 1],
  "Speck 128/256 block" => [fn ->  SpeckEx.speck128_256_encrypt!(block128, key256) end, tasks: 1],
}
|> Benchmark.bench_many()
|> Benchmark.format_results()
|> IO.puts()
