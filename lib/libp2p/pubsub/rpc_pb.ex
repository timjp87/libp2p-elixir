defmodule Libp2p.Pubsub.RPCPB do
  @moduledoc """
  Protobuf encoding/decoding for pubsub `RPC` messages.

  Schema (from `third_party/libp2p_specs/pubsub/README.md`):

  ```protobuf
  syntax = "proto2";
  message RPC {
    repeated SubOpts subscriptions = 1;
    repeated Message publish = 2;
    optional ControlMessage control = 3; // gossipsub
    message SubOpts {
      optional bool subscribe = 1;
      optional string topicid = 2;
    }
  }
  ```

  Gossipsub extends the base `RPC` with an optional `control` field; see
  `third_party/libp2p_specs/pubsub/gossipsub/gossipsub-v1.0.md` and
  `gossipsub-v1.1.md` for the full Control message details.
  """

  alias Libp2p.Protobuf
  alias Libp2p.Pubsub.MessagePB

  @type subopts :: %{subscribe: boolean(), topicid: binary()}

  @type control_ihave :: %{topicID: binary(), messageIDs: [binary()]}
  @type control_iwant :: %{messageIDs: [binary()]}
  @type control_graft :: %{topicID: binary()}

  @type peer_info :: %{
          peerID: binary() | nil,
          signedPeerRecord: binary() | nil
        }

  @type control_prune :: %{
          topicID: binary(),
          peers: [peer_info()],
          backoff: non_neg_integer() | nil
        }

  @type control_message :: %{
          ihave: [control_ihave()],
          iwant: [control_iwant()],
          graft: [control_graft()],
          prune: [control_prune()]
        }

  @type t :: %{
          subscriptions: [subopts()],
          publish: [map()],
          control: control_message() | nil
        }

  @spec encode_subopts(subopts()) :: binary()
  def encode_subopts(%{subscribe: sub, topicid: topic}) when is_boolean(sub) and is_binary(topic) do
    # deterministic tag order: 1,2
    Protobuf.encode_varint_field(1, if(sub, do: 1, else: 0)) <>
      Protobuf.encode_len_field(2, topic)
  end

  @spec decode_subopts(binary()) :: subopts()
  def decode_subopts(bin) when is_binary(bin) do
    fields = Protobuf.decode_fields(bin)

    sub =
      case Enum.find(fields, fn {n, _w, _v} -> n == 1 end) do
        {1, 0, 0} -> false
        {1, 0, 1} -> true
        _ -> raise ArgumentError, "missing or invalid SubOpts.subscribe"
      end

    topic =
      case Enum.find(fields, fn {n, _w, _v} -> n == 2 end) do
        {2, 2, v} when is_binary(v) -> v
        _ -> raise ArgumentError, "missing or invalid SubOpts.topicid"
      end

    %{subscribe: sub, topicid: topic}
  end

  @spec encode(t()) :: binary()
  def encode(%{subscriptions: subs, publish: pubs} = rpc) when is_list(subs) and is_list(pubs) do
    subs_bin = Enum.map(subs, fn s -> Protobuf.encode_len_field(1, encode_subopts(s)) end)
    pubs_bin = Enum.map(pubs, fn m -> Protobuf.encode_len_field(2, MessagePB.encode(m)) end)

    control_bin =
      case Map.get(rpc, :control) do
        nil -> []
        c -> [Protobuf.encode_len_field(3, encode_control(c))]
      end

    IO.iodata_to_binary(subs_bin ++ pubs_bin ++ control_bin)
  end

  @spec decode(binary()) :: t()
  def decode(bin) when is_binary(bin) do
    fields = Protobuf.decode_fields(bin)

    subs =
      fields
      |> Enum.filter(fn {n, w, _v} -> n == 1 and w == 2 end)
      |> Enum.map(fn {_n, _w, v} -> decode_subopts(v) end)

    pubs =
      fields
      |> Enum.filter(fn {n, w, _v} -> n == 2 and w == 2 end)
      |> Enum.map(fn {_n, _w, v} -> MessagePB.decode(v) end)

    control =
      case Enum.find(fields, fn {n, w, _v} -> n == 3 and w == 2 end) do
        {3, 2, v} when is_binary(v) -> decode_control(v)
        _ -> nil
      end

    %{subscriptions: subs, publish: pubs, control: control}
  end

  # --- gossipsub ControlMessage (proto2) ---

  @spec encode_control(control_message()) :: binary()
  def encode_control(%{} = c) do
    ihave = Map.get(c, :ihave, []) || []
    iwant = Map.get(c, :iwant, []) || []
    graft = Map.get(c, :graft, []) || []
    prune = Map.get(c, :prune, []) || []

    ihave_bin = Enum.map(ihave, fn m -> Protobuf.encode_len_field(1, encode_ihave(m)) end)
    iwant_bin = Enum.map(iwant, fn m -> Protobuf.encode_len_field(2, encode_iwant(m)) end)
    graft_bin = Enum.map(graft, fn m -> Protobuf.encode_len_field(3, encode_graft(m)) end)
    prune_bin = Enum.map(prune, fn m -> Protobuf.encode_len_field(4, encode_prune(m)) end)

    IO.iodata_to_binary(ihave_bin ++ iwant_bin ++ graft_bin ++ prune_bin)
  end

  @spec decode_control(binary()) :: control_message()
  def decode_control(bin) when is_binary(bin) do
    fields = Protobuf.decode_fields(bin)

    %{
      ihave:
        fields
        |> Enum.filter(fn {n, w, _} -> n == 1 and w == 2 end)
        |> Enum.map(fn {_, _, v} -> decode_ihave(v) end),
      iwant:
        fields
        |> Enum.filter(fn {n, w, _} -> n == 2 and w == 2 end)
        |> Enum.map(fn {_, _, v} -> decode_iwant(v) end),
      graft:
        fields
        |> Enum.filter(fn {n, w, _} -> n == 3 and w == 2 end)
        |> Enum.map(fn {_, _, v} -> decode_graft(v) end),
      prune:
        fields
        |> Enum.filter(fn {n, w, _} -> n == 4 and w == 2 end)
        |> Enum.map(fn {_, _, v} -> decode_prune(v) end)
    }
  end

  defp encode_ihave(%{topicID: topic, messageIDs: ids}) when is_binary(topic) and is_list(ids) do
    out = [Protobuf.encode_len_field(1, topic)]
    out = Enum.reduce(ids, out, fn id, acc -> [Protobuf.encode_len_field(2, id) | acc] end)
    out |> Enum.reverse() |> IO.iodata_to_binary()
  end

  defp decode_ihave(bin) do
    fields = Protobuf.decode_fields(bin)

    topic =
      case Enum.find(fields, fn {n, w, _} -> n == 1 and w == 2 end) do
        {1, 2, v} -> v
        _ -> raise ArgumentError, "missing ControlIHave.topicID"
      end

    ids =
      fields
      |> Enum.filter(fn {n, w, _} -> n == 2 and w == 2 end)
      |> Enum.map(fn {_, _, v} -> v end)

    %{topicID: topic, messageIDs: ids}
  end

  defp encode_iwant(%{messageIDs: ids}) when is_list(ids) do
    ids
    |> Enum.map(fn id -> Protobuf.encode_len_field(1, id) end)
    |> IO.iodata_to_binary()
  end

  defp decode_iwant(bin) do
    fields = Protobuf.decode_fields(bin)

    ids =
      fields
      |> Enum.filter(fn {n, w, _} -> n == 1 and w == 2 end)
      |> Enum.map(fn {_, _, v} -> v end)

    %{messageIDs: ids}
  end

  defp encode_graft(%{topicID: topic}) when is_binary(topic), do: Protobuf.encode_len_field(1, topic)

  defp decode_graft(bin) do
    fields = Protobuf.decode_fields(bin)

    topic =
      case Enum.find(fields, fn {n, w, _} -> n == 1 and w == 2 end) do
        {1, 2, v} -> v
        _ -> raise ArgumentError, "missing ControlGraft.topicID"
      end

    %{topicID: topic}
  end

  defp encode_prune(%{topicID: topic} = p) when is_binary(topic) do
    out = [Protobuf.encode_len_field(1, topic)]

    peers =
      (Map.get(p, :peers, []) || [])
      |> Enum.map(fn peer -> Protobuf.encode_len_field(2, encode_peer_info(peer)) end)

    out = Enum.reverse(peers) ++ out

    out =
      case Map.get(p, :backoff) do
        nil -> out
        n when is_integer(n) and n >= 0 -> [Protobuf.encode_varint_field(3, n) | out]
      end

    out |> Enum.reverse() |> IO.iodata_to_binary()
  end

  defp decode_prune(bin) do
    fields = Protobuf.decode_fields(bin)

    topic =
      case Enum.find(fields, fn {n, w, _} -> n == 1 and w == 2 end) do
        {1, 2, v} -> v
        _ -> raise ArgumentError, "missing ControlPrune.topicID"
      end

    peers =
      fields
      |> Enum.filter(fn {n, w, _} -> n == 2 and w == 2 end)
      |> Enum.map(fn {_, _, v} -> decode_peer_info(v) end)

    backoff =
      case Enum.find(fields, fn {n, w, _} -> n == 3 and w == 0 end) do
        {3, 0, v} when is_integer(v) -> v
        _ -> nil
      end

    %{topicID: topic, peers: peers, backoff: backoff}
  end

  defp encode_peer_info(peer) when is_map(peer) do
    out = []

    out =
      if Map.get(peer, :peerID) != nil do
        [Protobuf.encode_len_field(1, peer.peerID) | out]
      else
        out
      end

    out =
      if Map.get(peer, :signedPeerRecord) != nil do
        [Protobuf.encode_len_field(2, peer.signedPeerRecord) | out]
      else
        out
      end

    out |> Enum.reverse() |> IO.iodata_to_binary()
  end

  defp decode_peer_info(bin) do
    fields = Protobuf.decode_fields(bin)

    %{
      peerID:
        case Enum.find(fields, fn {n, w, _} -> n == 1 and w == 2 end) do
          {1, 2, v} -> v
          _ -> nil
        end,
      signedPeerRecord:
        case Enum.find(fields, fn {n, w, _} -> n == 2 and w == 2 end) do
          {2, 2, v} -> v
          _ -> nil
        end
    }
  end
end
