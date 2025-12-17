defmodule Libp2p.IdentifyPB do
  @moduledoc """
  Protobuf encoding/decoding for the Identify message.

  This targets `/ipfs/id/1.0.0` and implements the classic fields:
  (field numbers per `identify/src/generated/structs.proto` in rust-libp2p)
  1 publicKey (bytes)  -- libp2p-crypto PublicKey protobuf
  2 listenAddrs (repeated bytes) -- multiaddr bytes
  3 protocols (repeated string)
  4 observedAddr (bytes) -- multiaddr bytes
  5 protocolVersion (string)
  6 agentVersion (string)
  8 signedPeerRecord (bytes) -- optional (ignored for now)
  """

  alias Libp2p.Protobuf

  @type t :: %{
          protocol_version: binary() | nil,
          agent_version: binary() | nil,
          public_key: binary() | nil,
          listen_addrs: [binary()],
          observed_addr: binary() | nil,
          protocols: [binary()],
          signed_peer_record: binary() | nil
        }

  @spec encode(t()) :: binary()
  def encode(msg) when is_map(msg) do
    out = []

    out =
      if Map.get(msg, :public_key) != nil do
        [Protobuf.encode_len_field(1, msg.public_key) | out]
      else
        out
      end

    out =
      (Map.get(msg, :listen_addrs, []) || [])
      |> Enum.reduce(out, fn a, acc -> [Protobuf.encode_len_field(2, a) | acc] end)

    out =
      (Map.get(msg, :protocols, []) || [])
      |> Enum.reduce(out, fn p, acc -> [Protobuf.encode_len_field(3, p) | acc] end)

    out =
      if Map.get(msg, :observed_addr) != nil do
        [Protobuf.encode_len_field(4, msg.observed_addr) | out]
      else
        out
      end

    out =
      if Map.get(msg, :protocol_version) != nil do
        [Protobuf.encode_len_field(5, msg.protocol_version) | out]
      else
        out
      end

    out =
      if Map.get(msg, :agent_version) != nil do
        [Protobuf.encode_len_field(6, msg.agent_version) | out]
      else
        out
      end

    out =
      if Map.get(msg, :signed_peer_record) != nil do
        [Protobuf.encode_len_field(8, msg.signed_peer_record) | out]
      else
        out
      end

    out |> Enum.reverse() |> IO.iodata_to_binary()
  end

  @spec decode(binary()) :: t()
  def decode(bin) when is_binary(bin) do
    fields = Protobuf.decode_fields(bin)

    %{
      public_key: get_opt(fields, 1),
      listen_addrs: get_rep(fields, 2),
      protocols: get_rep(fields, 3),
      observed_addr: get_opt(fields, 4),
      protocol_version: get_opt(fields, 5),
      agent_version: get_opt(fields, 6),
      signed_peer_record: get_opt(fields, 8)
    }
  end

  defp get_opt(fields, n) do
    case Enum.find(fields, fn {n2, w, _v} -> n2 == n and w == 2 end) do
      {^n, 2, v} when is_binary(v) -> v
      _ -> nil
    end
  end

  defp get_rep(fields, n) do
    fields
    |> Enum.filter(fn {n2, w, _v} -> n2 == n and w == 2 end)
    |> Enum.map(fn {_n, _w, v} -> v end)
  end
end
