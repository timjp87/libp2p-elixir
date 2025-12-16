defmodule Libp2p.Pubsub do
  @moduledoc """
  PubSub interface and gossipsub implementation entry points.

  Target: gossipsub v1.1 with StrictNoSign policy and pluggable message-id.
  """

  alias Libp2p.Pubsub.{MessagePB, RPCPB}

  @doc """
  Build a strict-no-sign pubsub `Message` for a topic.
  """
  @spec build_strict_no_sign_message(binary(), binary()) :: map()
  def build_strict_no_sign_message(topic, data) when is_binary(topic) and is_binary(data) do
    %{topic: topic, data: data, from: nil, seqno: nil, signature: nil, key: nil}
  end

  @spec encode_rpc(map()) :: binary()
  def encode_rpc(rpc), do: RPCPB.encode(rpc)

  @spec decode_rpc(binary()) :: map()
  def decode_rpc(bin), do: RPCPB.decode(bin)

  @spec encode_message(map()) :: binary()
  def encode_message(msg), do: MessagePB.encode(msg)

  @spec decode_message(binary()) :: map()
  def decode_message(bin), do: MessagePB.decode(bin)

  @spec validate_strict_no_sign!(map()) :: :ok
  def validate_strict_no_sign!(msg), do: MessagePB.validate_strict_no_sign!(msg)
end
