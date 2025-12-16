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
  def speck32_64_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  def speck32_64_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  def speck32_64_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck48/72
  def speck48_72_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  def speck48_72_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  def speck48_72_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck48/96
  def speck48_96_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  def speck48_96_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  def speck48_96_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck64/96
  def speck64_96_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  def speck64_96_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  def speck64_96_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck64/128
  def speck64_128_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  def speck64_128_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  def speck64_128_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck96/96
  def speck96_96_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  def speck96_96_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  def speck96_96_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck96/144
  def speck96_144_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  def speck96_144_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  def speck96_144_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck128/128
  def speck128_128_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  def speck128_128_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  def speck128_128_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck128/192
  def speck128_192_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  def speck128_192_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  def speck128_192_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # Speck128/256
  def speck128_256_init(_key), do: :erlang.nif_error(:nif_not_loaded)
  def speck128_256_encrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)
  def speck128_256_decrypt(_data, _ref), do: :erlang.nif_error(:nif_not_loaded)

  # CTR mode functions
  # Speck32/64
  def speck32_64_ctr_encrypt(_key, _nonce, _data), do: :erlang.nif_error(:nif_not_loaded)
  def speck32_64_ctr_decrypt(_key, _nonce, _data), do: :erlang.nif_error(:nif_not_loaded)

  # Speck64/96
  def speck64_96_ctr_encrypt(_key, _nonce, _data), do: :erlang.nif_error(:nif_not_loaded)
  def speck64_96_ctr_decrypt(_key, _nonce, _data), do: :erlang.nif_error(:nif_not_loaded)

  # Speck64/128
  def speck64_128_ctr_encrypt(_key, _nonce, _data), do: :erlang.nif_error(:nif_not_loaded)
  def speck64_128_ctr_decrypt(_key, _nonce, _data), do: :erlang.nif_error(:nif_not_loaded)

  # Speck128/128
  def speck128_128_ctr_encrypt(_key, _nonce, _data), do: :erlang.nif_error(:nif_not_loaded)
  def speck128_128_ctr_decrypt(_key, _nonce, _data), do: :erlang.nif_error(:nif_not_loaded)

  # Speck128/192
  def speck128_192_ctr_encrypt(_key, _nonce, _data), do: :erlang.nif_error(:nif_not_loaded)
  def speck128_192_ctr_decrypt(_key, _nonce, _data), do: :erlang.nif_error(:nif_not_loaded)

  # Speck128/256
  def speck128_256_ctr_encrypt(_key, _nonce, _data), do: :erlang.nif_error(:nif_not_loaded)
  def speck128_256_ctr_decrypt(_key, _nonce, _data), do: :erlang.nif_error(:nif_not_loaded)
end
