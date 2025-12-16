defmodule Libp2p.Base58btc do
  @moduledoc """
  Base58btc encoding (Bitcoin alphabet).
  """

  @alphabet ~c"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  @alphabet_map @alphabet |> Enum.with_index() |> Map.new()

  @spec encode(binary()) :: binary()
  def encode(bin) when is_binary(bin) do
    {leading_zeros, rest} = count_leading_zeros(bin)

    out =
      if rest == <<>> do
        []
      else
        encode_digits(:binary.decode_unsigned(rest), [])
      end

    zeros_prefix = List.duplicate(hd(@alphabet), leading_zeros)
    (zeros_prefix ++ out) |> IO.iodata_to_binary()
  end

  @spec decode(binary()) :: binary()
  def decode(str) when is_binary(str) do
    chars = :binary.bin_to_list(str)
    {leading_ones, rest} = count_leading_ones(chars)

    n =
      Enum.reduce(rest, 0, fn ch, acc ->
        digit =
          case Map.fetch(@alphabet_map, ch) do
            {:ok, d} -> d
            :error -> raise ArgumentError, "invalid base58btc character: #{inspect(<<ch>>)}"
          end

        acc * 58 + digit
      end)

    body =
      if rest == [] do
        <<>>
      else
        :binary.encode_unsigned(n)
      end

    :binary.copy(<<0>>, leading_ones) <> body
  end

  defp encode_digits(0, acc), do: acc

  defp encode_digits(n, acc) do
    q = div(n, 58)
    r = rem(n, 58)
    ch = Enum.at(@alphabet, r)
    encode_digits(q, [<<ch>> | acc])
  end

  defp count_leading_zeros(bin), do: count_leading_zeros(bin, 0)
  defp count_leading_zeros(<<0, rest::binary>>, n), do: count_leading_zeros(rest, n + 1)
  defp count_leading_zeros(rest, n), do: {n, rest}

  defp count_leading_ones(chars), do: count_leading_ones(chars, 0)
  defp count_leading_ones([?1 | rest], n), do: count_leading_ones(rest, n + 1)
  defp count_leading_ones(rest, n), do: {n, rest}
end
