defmodule Libp2p.Gossipsub.Framing do
  @moduledoc """
  Length-delimited protobuf framing used on pubsub/gossipsub streams.

  Frames are encoded as:
  - uvarint length
  - protobuf bytes (length bytes)
  """

  alias Libp2p.Varint

  @spec encode(binary()) :: binary()
  def encode(bin) when is_binary(bin) do
    Varint.encode_u64(byte_size(bin)) <> bin
  end

  @spec decode_one(binary()) :: {binary(), binary()} | :more
  def decode_one(buf) when is_binary(buf) do
    try do
      {len, rest} = Varint.decode_u64(buf)
      if byte_size(rest) < len, do: :more, else: decode_len(rest, len)
    rescue
      ArgumentError -> :more
    end
  end

  defp decode_len(rest, len) do
    <<msg::binary-size(len), tail::binary>> = rest
    {msg, tail}
  end

  @spec decode_all(binary(), [binary()]) :: {[binary()], binary()}
  def decode_all(buf, acc \\ []) do
    case decode_one(buf) do
      :more ->
        {Enum.reverse(acc), buf}

      {msg, tail} ->
        decode_all(tail, [msg | acc])
    end
  end
end
