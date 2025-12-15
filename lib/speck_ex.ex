defmodule SpeckEx do
  @moduledoc """
  A Rust-backed implementation of the Speck block cipher using NIF Resources.
  """
  alias SpeckEx.Block
  alias SpeckEx.Native

  @doc """
  Initializes the cipher state with a key and mode.
  Delegates to `SpeckEx.Block.init/2`.
  """
  def init(key, mode) do
    Block.init(key, mode)
  end

  @doc """
  Encrypts or decrypts data using CTR mode.
  Since CTR mode is symmetric, this function handles both encryption and decryption.
  """
  def encrypt(data, key_ref, iv) do
    case Native.ctr_crypt_nif(data, key_ref, iv) do
      {:error, _} = error -> error
      ciphertext -> {:ok, ciphertext}
    end
  end
end
