defmodule Libp2p.RequestResponse.Framing do
  @moduledoc """
  Simple length-delimited framing for request/response messages.

  This is *not* Ethereum SSZ-snappy framing; callers can wrap with their own codec.
  We provide it as a default for integration tests and simple protocols.
  """

  alias Libp2p.Varint

  @spec encode(binary()) :: binary()
  def encode(bin) when is_binary(bin), do: Varint.encode_u64(byte_size(bin)) <> bin

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
end
