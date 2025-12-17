defmodule Libp2p.Noise.HandshakePayloadPB do
  @moduledoc """
  Protobuf encoding/decoding for `NoiseHandshakePayload` (noise-libp2p spec).

  From `noise/README.md`:
  - field 1: identity_key (bytes) = serialized libp2p `PublicKey` protobuf
  - field 2: identity_sig (bytes)
  - field 4: extensions (NoiseExtensions)
  """

  alias Libp2p.Protobuf
  alias Libp2p.Varint

  @wire_len 2

  @type extensions :: %{
          optional(:webtransport_certhashes) => [binary()],
          optional(:stream_muxers) => [binary()]
        }

  @spec encode(%{optional(:extensions) => binary() | nil, identity_key: binary(), identity_sig: binary()}) :: binary()
  def encode(%{identity_key: ik, identity_sig: sig} = msg) when is_binary(ik) and is_binary(sig) do
    # Deterministic tag order: 1, 2, 4.
    tag1 = Varint.encode_u64((1 <<< 3) ||| @wire_len)
    tag2 = Varint.encode_u64((2 <<< 3) ||| @wire_len)
    ext = Map.get(msg, :extensions, nil)

    base = tag1 <> Varint.encode_u64(byte_size(ik)) <> ik <> tag2 <> Varint.encode_u64(byte_size(sig)) <> sig

    if is_binary(ext) do
      tag4 = Varint.encode_u64((4 <<< 3) ||| @wire_len)
      base <> tag4 <> Varint.encode_u64(byte_size(ext)) <> ext
    else
      base
    end
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

  @doc """
  Encode a NoiseExtensions message.

  Currently used for `stream_muxers` (field 2) as described in `libp2p_specs/noise/README.md`.
  """
  @spec encode_extensions(extensions()) :: binary()
  def encode_extensions(ext) when is_map(ext) do
    out = []

    out =
      (Map.get(ext, :webtransport_certhashes, []) || [])
      |> Enum.reduce(out, fn h, acc -> [Protobuf.encode_len_field(1, h) | acc] end)

    out =
      (Map.get(ext, :stream_muxers, []) || [])
      |> Enum.reduce(out, fn m, acc -> [Protobuf.encode_len_field(2, m) | acc] end)

    out |> Enum.reverse() |> IO.iodata_to_binary()
  end

  @spec decode_extensions(binary() | nil) :: %{webtransport_certhashes: [binary()], stream_muxers: [binary()]}
  def decode_extensions(nil), do: %{webtransport_certhashes: [], stream_muxers: []}
  def decode_extensions(ext_bin) when is_binary(ext_bin) do
    fields = Protobuf.decode_fields(ext_bin)

    %{
      webtransport_certhashes: get_rep(fields, 1),
      stream_muxers: get_rep(fields, 2)
    }
  end

  defp get_rep(fields, n) do
    fields
    |> Enum.filter(fn {n2, w, _v} -> n2 == n and w == @wire_len end)
    |> Enum.map(fn {_n, _w, v} -> v end)
  end

  defp bor(a, b), do: :erlang.bor(a, b)
  defp bsl(a, b), do: :erlang.bsl(a, b)
  defp a <<< b, do: bsl(a, b)
  defp a ||| b, do: bor(a, b)
end
