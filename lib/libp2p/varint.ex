defmodule Libp2p.Varint do
  @moduledoc """
  Unsigned varint encoding (protobuf-style).
  """

  @spec encode_u64(non_neg_integer()) :: binary()
  def encode_u64(n) when is_integer(n) and n >= 0 do
    do_encode_u64(n, []) |> IO.iodata_to_binary()
  end

  @spec decode_u64(binary()) :: {non_neg_integer(), binary()}
  def decode_u64(bin) when is_binary(bin) do
    do_decode_u64(bin, 0, 0)
  end

  defp do_encode_u64(n, acc) when n < 0x80 do
    Enum.reverse([<<n>> | acc])
  end

  defp do_encode_u64(n, acc) do
    byte = bor(band(n, 0x7F), 0x80)
    do_encode_u64(bsr(n, 7), [<<byte>> | acc])
  end

  defp do_decode_u64(<<>>, _shift, _acc), do: raise(ArgumentError, "truncated varint")

  defp do_decode_u64(<<byte, rest::binary>>, shift, acc) when shift < 64 do
    value = bor(acc, bsl(band(byte, 0x7F), shift))

    if band(byte, 0x80) == 0 do
      {value, rest}
    else
      do_decode_u64(rest, shift + 7, value)
    end
  end

  defp do_decode_u64(_bin, _shift, _acc), do: raise(ArgumentError, "varint overflow")

  defp band(a, b), do: :erlang.band(a, b)
  defp bor(a, b), do: :erlang.bor(a, b)
  defp bsr(a, b), do: :erlang.bsr(a, b)
  defp bsl(a, b), do: :erlang.bsl(a, b)
end
