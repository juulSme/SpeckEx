defmodule SpeckEx.Native do
  use Rustler, otp_app: :speck_ex, crate: "speck_ex"

  def init_nif(_key, _mode), do: :erlang.nif_error(:nif_not_loaded)
  def block_crypt_nif(_data, _ref, _decrypt?), do: :erlang.nif_error(:nif_not_loaded)
  def ctr_crypt_nif(_data, _ref, _iv), do: :erlang.nif_error(:nif_not_loaded)
end
