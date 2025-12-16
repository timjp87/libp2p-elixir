defmodule Libp2p.Pubsub.RPCPB do
  @moduledoc """
  Protobuf encoding/decoding for pubsub `RPC` messages.

  Schema (from `third_party/libp2p_specs/pubsub/README.md`):

  ```protobuf
  syntax = "proto2";
  message RPC {
    repeated SubOpts subscriptions = 1;
    repeated Message publish = 2;
    message SubOpts {
      optional bool subscribe = 1;
      optional string topicid = 2;
    }
  }
  ```
  """

  alias Libp2p.Protobuf
  alias Libp2p.Pubsub.MessagePB

  @type subopts :: %{subscribe: boolean(), topicid: binary()}
  @type t :: %{subscriptions: [subopts()], publish: [map()]}

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
  def encode(%{subscriptions: subs, publish: pubs}) when is_list(subs) and is_list(pubs) do
    subs_bin = Enum.map(subs, fn s -> Protobuf.encode_len_field(1, encode_subopts(s)) end)
    pubs_bin = Enum.map(pubs, fn m -> Protobuf.encode_len_field(2, MessagePB.encode(m)) end)
    IO.iodata_to_binary(subs_bin ++ pubs_bin)
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

    %{subscriptions: subs, publish: pubs}
  end
end
