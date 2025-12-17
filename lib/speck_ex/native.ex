defmodule SpeckEx.Native do
  version = Mix.Project.config()[:version]

  use RustlerPrecompiled,
    otp_app: :speck_ex,
    crate: "speck_ex",
    base_url: "https://github.com/juulSme/SpeckEx/releases/download/v#{version}",
    version: version,
    targets: [
      "aarch64-apple-darwin",
      "aarch64-unknown-linux-gnu",
      "aarch64-unknown-linux-musl",
      "arm-unknown-linux-gnueabihf",
      "riscv64gc-unknown-linux-gnu",
      "x86_64-pc-windows-gnu",
      "x86_64-pc-windows-msvc",
      "x86_64-unknown-linux-gnu",
      "x86_64-unknown-linux-musl"
    ]

  # Speck32/64
  @spec speck32_64_init(<<_::64>>) :: reference()
  def speck32_64_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck32_64_encrypt(<<_::32>>, reference()) :: <<_::32>>
  def speck32_64_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck32_64_decrypt(<<_::32>>, reference()) :: <<_::32>>
  def speck32_64_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck48/72
  @spec speck48_72_init(<<_::72>>) :: reference()
  def speck48_72_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck48_72_encrypt(<<_::48>>, reference()) :: <<_::48>>
  def speck48_72_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck48_72_decrypt(<<_::48>>, reference()) :: <<_::48>>
  def speck48_72_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck48/96
  @spec speck48_96_init(<<_::96>>) :: reference()
  def speck48_96_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck48_96_encrypt(<<_::48>>, reference()) :: <<_::48>>
  def speck48_96_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck48_96_decrypt(<<_::48>>, reference()) :: <<_::48>>
  def speck48_96_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck64/96
  @spec speck64_96_init(<<_::96>>) :: reference()
  def speck64_96_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck64_96_encrypt(<<_::64>>, reference()) :: <<_::64>>
  def speck64_96_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck64_96_decrypt(<<_::64>>, reference()) :: <<_::64>>
  def speck64_96_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck64/128
  @spec speck64_128_init(<<_::128>>) :: reference()
  def speck64_128_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck64_128_encrypt(<<_::64>>, reference()) :: <<_::64>>
  def speck64_128_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck64_128_decrypt(<<_::64>>, reference()) :: <<_::64>>
  def speck64_128_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck96/96
  @spec speck96_96_init(<<_::96>>) :: reference()
  def speck96_96_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck96_96_encrypt(<<_::96>>, reference()) :: <<_::96>>
  def speck96_96_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck96_96_decrypt(<<_::96>>, reference()) :: <<_::96>>
  def speck96_96_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck96/144
  @spec speck96_144_init(<<_::144>>) :: reference()
  def speck96_144_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck96_144_encrypt(<<_::96>>, reference()) :: <<_::96>>
  def speck96_144_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck96_144_decrypt(<<_::96>>, reference()) :: <<_::96>>
  def speck96_144_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck128/128
  @spec speck128_128_init(<<_::128>>) :: reference()
  def speck128_128_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck128_128_encrypt(<<_::128>>, reference()) :: <<_::128>>
  def speck128_128_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck128_128_decrypt(<<_::128>>, reference()) :: <<_::128>>
  def speck128_128_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck128/192
  @spec speck128_192_init(<<_::192>>) :: reference()
  def speck128_192_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck128_192_encrypt(<<_::128>>, reference()) :: <<_::128>>
  def speck128_192_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck128_192_decrypt(<<_::128>>, reference()) :: <<_::128>>
  def speck128_192_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck128/256
  @spec speck128_256_init(<<_::256>>) :: reference()
  def speck128_256_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck128_256_encrypt(<<_::128>>, reference()) :: <<_::128>>
  def speck128_256_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck128_256_decrypt(<<_::128>>, reference()) :: <<_::128>>
  def speck128_256_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # CTR mode functions
  # Speck32/64
  @spec speck32_64_ctr_encrypt(<<_::64>>, <<_::32>>, binary()) :: binary()
  def speck32_64_ctr_encrypt(_key, _iv, _data), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck32_64_ctr_decrypt(<<_::64>>, <<_::32>>, binary()) :: binary()
  def speck32_64_ctr_decrypt(_key, _iv, _data), do: :erlang.nif_error(:nif_not_loaded)

  # Speck64/96
  @spec speck64_96_ctr_encrypt(<<_::96>>, <<_::64>>, binary()) :: binary()
  def speck64_96_ctr_encrypt(_key, _iv, _data), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck64_96_ctr_decrypt(<<_::96>>, <<_::64>>, binary()) :: binary()
  def speck64_96_ctr_decrypt(_key, _iv, _data), do: :erlang.nif_error(:nif_not_loaded)

  # Speck64/128
  @spec speck64_128_ctr_encrypt(<<_::128>>, <<_::64>>, binary()) :: binary()
  def speck64_128_ctr_encrypt(_key, _iv, _data), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck64_128_ctr_decrypt(<<_::128>>, <<_::64>>, binary()) :: binary()
  def speck64_128_ctr_decrypt(_key, _iv, _data), do: :erlang.nif_error(:nif_not_loaded)

  # Speck128/128
  @spec speck128_128_ctr_encrypt(<<_::128>>, <<_::128>>, binary()) :: binary()
  def speck128_128_ctr_encrypt(_key, _iv, _data), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck128_128_ctr_decrypt(<<_::128>>, <<_::128>>, binary()) :: binary()
  def speck128_128_ctr_decrypt(_key, _iv, _data), do: :erlang.nif_error(:nif_not_loaded)

  # Speck128/192
  @spec speck128_192_ctr_encrypt(<<_::192>>, <<_::128>>, binary()) :: binary()
  def speck128_192_ctr_encrypt(_key, _iv, _data), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck128_192_ctr_decrypt(<<_::192>>, <<_::128>>, binary()) :: binary()
  def speck128_192_ctr_decrypt(_key, _iv, _data), do: :erlang.nif_error(:nif_not_loaded)

  # Speck128/256
  @spec speck128_256_ctr_encrypt(<<_::256>>, <<_::128>>, binary()) :: binary()
  def speck128_256_ctr_encrypt(_key, _iv, _data), do: :erlang.nif_error(:nif_not_loaded)
  @spec speck128_256_ctr_decrypt(<<_::256>>, <<_::128>>, binary()) :: binary()
  def speck128_256_ctr_decrypt(_key, _iv, _data), do: :erlang.nif_error(:nif_not_loaded)
end
