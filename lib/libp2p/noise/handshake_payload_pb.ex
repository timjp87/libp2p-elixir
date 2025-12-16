defmodule Libp2p.Noise.HandshakePayloadPB do
  @moduledoc """
  Protobuf encoding/decoding for `NoiseHandshakePayload` (noise-libp2p spec).

  From `noise/README.md`:
  - field 1: identity_key (bytes) = serialized libp2p `PublicKey` protobuf
  - field 2: identity_sig (bytes)
  - field 4: extensions (ignored for now)
  """

  alias Libp2p.Protobuf
  alias Libp2p.Varint

  @wire_len 2

  @spec encode(%{identity_key: binary(), identity_sig: binary()}) :: binary()
  def encode(%{identity_key: ik, identity_sig: sig}) when is_binary(ik) and is_binary(sig) do
    # Deterministic tag order: 1, 2. (extensions omitted)
    tag1 = Varint.encode_u64((1 <<< 3) ||| @wire_len)
    tag2 = Varint.encode_u64((2 <<< 3) ||| @wire_len)

    tag1 <> Varint.encode_u64(byte_size(ik)) <> ik <> tag2 <> Varint.encode_u64(byte_size(sig)) <> sig
  end

  @spec decode(binary()) :: %{identity_key: binary(), identity_sig: binary(), extensions: binary() | nil}
  def decode(bin) when is_binary(bin) do
    fields = Protobuf.decode_fields(bin)

    ik =
      case Enum.find(fields, fn {n, _w, _v} -> n == 1 end) do
        {1, @wire_len, v} when is_binary(v) -> v
        _ -> raise ArgumentError, "missing NoiseHandshakePayload.identity_key"
      end

    sig =
      case Enum.find(fields, fn {n, _w, _v} -> n == 2 end) do
        {2, @wire_len, v} when is_binary(v) -> v
        _ -> raise ArgumentError, "missing NoiseHandshakePayload.identity_sig"
      end

    ext =
      case Enum.find(fields, fn {n, _w, _v} -> n == 4 end) do
        {4, @wire_len, v} when is_binary(v) -> v
        _ -> nil
      end

    %{identity_key: ik, identity_sig: sig, extensions: ext}
  end

  defp bor(a, b), do: :erlang.bor(a, b)
  defp bsl(a, b), do: :erlang.bsl(a, b)
  defp a <<< b, do: bsl(a, b)
  defp a ||| b, do: bor(a, b)
end
