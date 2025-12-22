defmodule Libp2p.Pubsub.MessagePB do
  @moduledoc """
  Protobuf encoding/decoding for pubsub `Message`.

  Schema (from `third_party/libp2p_specs/pubsub/README.md`):

  ```protobuf
  syntax = "proto2";
  message Message {
    optional string from = 1;
    optional bytes data = 2;
    optional bytes seqno = 3;
    required string topic = 4;
    optional bytes signature = 5;
    optional bytes key = 6;
  }
  ```

  This module supports `StrictNoSign` validation helpers.
  """

  alias Libp2p.Protobuf

  @type t :: %{
          topic: binary(),
          data: binary() | nil,
          from: binary() | nil,
          seqno: binary() | nil,
          signature: binary() | nil,
          key: binary() | nil
        }

  @spec encode(t()) :: binary()
  def encode(%{topic: topic} = msg) when is_binary(topic) do
    # tag order: 1..6
    out = []

    out =
      if Map.get(msg, :from) != nil, do: [Protobuf.encode_len_field(1, msg.from) | out], else: out

    out =
      if Map.get(msg, :data) != nil, do: [Protobuf.encode_len_field(2, msg.data) | out], else: out

    out =
      if Map.get(msg, :seqno) != nil,
        do: [Protobuf.encode_len_field(3, msg.seqno) | out],
        else: out

    out = [Protobuf.encode_len_field(4, topic) | out]

    out =
      if Map.get(msg, :signature) != nil,
        do: [Protobuf.encode_len_field(5, msg.signature) | out],
        else: out

    out =
      if Map.get(msg, :key) != nil, do: [Protobuf.encode_len_field(6, msg.key) | out], else: out

    out |> Enum.reverse() |> IO.iodata_to_binary()
  end

  @spec decode(binary()) :: t()
  def decode(bin) when is_binary(bin) do
    fields = Protobuf.decode_fields(bin)

    topic =
      case Enum.find(fields, fn {n, _w, _v} -> n == 4 end) do
        {4, 2, v} when is_binary(v) -> v
        _ -> raise ArgumentError, "missing Message.topic"
      end

    %{
      from: get_opt(fields, 1),
      data: get_opt(fields, 2),
      seqno: get_opt(fields, 3),
      topic: topic,
      signature: get_opt(fields, 5),
      key: get_opt(fields, 6)
    }
  end

  @doc """
  Validate `StrictNoSign` policy: `from`, `seqno`, `signature`, `key` MUST be absent.
  """
  @spec validate_strict_no_sign!(t()) :: :ok
  def validate_strict_no_sign!(msg) when is_map(msg) do
    cond do
      Map.get(msg, :from) != nil ->
        raise ArgumentError, "StrictNoSign violation: from present"

      Map.get(msg, :seqno) != nil ->
        raise ArgumentError, "StrictNoSign violation: seqno present"

      Map.get(msg, :signature) != nil ->
        raise ArgumentError, "StrictNoSign violation: signature present"

      Map.get(msg, :key) != nil ->
        raise ArgumentError, "StrictNoSign violation: key present"

      true ->
        :ok
    end
  end

  defp get_opt(fields, n) do
    case Enum.find(fields, fn {n2, w, _v} -> n2 == n and w == 2 end) do
      {^n, 2, v} when is_binary(v) -> v
      _ -> nil
    end
  end
end
