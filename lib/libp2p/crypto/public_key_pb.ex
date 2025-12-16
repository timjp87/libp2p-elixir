defmodule Libp2p.Crypto.PublicKeyPB do
  @moduledoc """
  Minimal encoding for the libp2p-crypto `PublicKey` protobuf message.

  Schema (legacy libp2p):
  - field 1: `Type` (varint enum)
  - field 2: `Data` (bytes)
  """

  alias Libp2p.Protobuf
  alias Libp2p.Varint

  @type key_type :: :rsa | :ed25519 | :secp256k1 | :ecdsa

  @spec encode_public_key(key_type(), binary()) :: binary()
  def encode_public_key(type, data) when is_binary(data) do
    type_num =
      case type do
        :rsa -> 0
        :ed25519 -> 1
        :secp256k1 -> 2
        :ecdsa -> 3
      end

    # tag = (field_number << 3) | wire_type
    # wire types: 0 varint, 2 length-delimited
    tag_type = Varint.encode_u64((1 <<< 3) ||| 0)
    tag_data = Varint.encode_u64((2 <<< 3) ||| 2)

    tag_type <>
      Varint.encode_u64(type_num) <>
      tag_data <>
      Varint.encode_u64(byte_size(data)) <>
      data
  end

  @spec decode_public_key(binary()) :: {key_type(), binary()}
  def decode_public_key(bin) when is_binary(bin) do
    fields = Protobuf.decode_fields(bin)

    type_num =
      case Enum.find(fields, fn {n, _w, _v} -> n == 1 end) do
        {1, 0, v} when is_integer(v) -> v
        _ -> raise ArgumentError, "missing PublicKey.Type"
      end

    data =
      case Enum.find(fields, fn {n, _w, _v} -> n == 2 end) do
        {2, 2, v} when is_binary(v) -> v
        _ -> raise ArgumentError, "missing PublicKey.Data"
      end

    type =
      case type_num do
        0 -> :rsa
        1 -> :ed25519
        2 -> :secp256k1
        3 -> :ecdsa
        other -> raise ArgumentError, "unknown PublicKey.Type enum #{other}"
      end

    {type, data}
  end

  defp bor(a, b), do: :erlang.bor(a, b)
  defp bsl(a, b), do: :erlang.bsl(a, b)

  # allow use of <<< and ||| without pulling Bitwise everywhere
  defp a <<< b, do: bsl(a, b)
  defp a ||| b, do: bor(a, b)
end
