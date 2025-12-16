defmodule SpeckEx.Native do
  use Rustler, otp_app: :speck_ex, crate: "speck_ex"

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
end
