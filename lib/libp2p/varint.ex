defmodule Libp2p.Varint do
  @moduledoc """
  Unsigned varint encoding (protobuf-style).
  """

  @spec encode_u64(non_neg_integer()) :: binary()
  def encode_u64(n) when is_integer(n) and n >= 0 do
    do_encode_u64(n, []) |> IO.iodata_to_binary()
  end

  defp do_encode_u64(n, acc) when n < 0x80 do
    Enum.reverse([<<n>> | acc])
  end

  defp do_encode_u64(n, acc) do
    byte = bor(band(n, 0x7F), 0x80)
    do_encode_u64(bsr(n, 7), [<<byte>> | acc])
  end

  defp band(a, b), do: :erlang.band(a, b)
  defp bor(a, b), do: :erlang.bor(a, b)
  defp bsr(a, b), do: :erlang.bsr(a, b)
end
