defmodule SpeckEx.Block do
  @moduledoc """
  Raw interface for the Speck Block Cipher.
  WARNING: This encrypts single blocks (ECB-style). Do not use directly for loose data.
  """
  alias SpeckEx.Native

  @type mode :: :speck64_128 | :speck96_144 | :speck128_256
  @type key_ref :: reference()

  @doc "Initializes the key schedule."
  @spec init(binary(), mode()) :: {:ok, reference()} | {:error, binary()}
  def init(key, mode) do
    with :ok <- validate_key_size(mode, byte_size(key)),
         key_ref when is_reference(key_ref) <- Native.init_nif(key, mode) do
      {:ok, key_ref}
    else
      {:error, reason} -> {:error, reason}
      error -> {:error, "Failed to initialize: #{inspect(error)}"}
    end
  end

  @spec encrypt(binary(), key_ref()) :: {:ok, binary()} | {:error, binary()}
  @doc "Encrypts a SINGLE block."
  def encrypt(block, key_ref) do
    Native.block_crypt_nif(block, key_ref, false)
  end

  @doc "Decrypts a SINGLE block."
  @spec decrypt(binary(), key_ref()) :: {:ok, binary()} | {:error, binary()}
  def decrypt(block, key_ref) do
    Native.block_crypt_nif(block, key_ref, true)
  end

  # Helpers
  defp validate_key_size(:speck64_128, 16), do: :ok
  defp validate_key_size(:speck96_144, 18), do: :ok
  defp validate_key_size(:speck128_256, 32), do: :ok
  defp validate_key_size(mode, s), do: {:error, "Invalid key size for #{mode}: #{s}"}
end
