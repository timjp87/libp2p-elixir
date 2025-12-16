defmodule Libp2p.Protobuf do
  @moduledoc """
  Minimal protobuf (proto2/proto3) decoding helpers sufficient for libp2p specs.

  This is intentionally not a general-purpose protobuf implementation.
  """

  alias Libp2p.Varint

  @wire_varint 0
  @wire_len 2

  @type field :: {non_neg_integer(), non_neg_integer(), integer() | binary()}

  @doc "Encode a (field_no, wire_type) tag as a uvarint."
  @spec encode_tag(non_neg_integer(), non_neg_integer()) :: binary()
  def encode_tag(field_no, wire_type)
      when is_integer(field_no) and field_no > 0 and is_integer(wire_type) and wire_type in [@wire_varint, @wire_len] do
    Varint.encode_u64(field_no * 8 + wire_type)
  end

  @doc "Encode a varint field."
  @spec encode_varint_field(non_neg_integer(), non_neg_integer()) :: binary()
  def encode_varint_field(field_no, value) when is_integer(value) and value >= 0 do
    encode_tag(field_no, @wire_varint) <> Varint.encode_u64(value)
  end

  @doc "Encode a length-delimited field (bytes or nested message)."
  @spec encode_len_field(non_neg_integer(), binary()) :: binary()
  def encode_len_field(field_no, bytes) when is_binary(bytes) do
    encode_tag(field_no, @wire_len) <> Varint.encode_u64(byte_size(bytes)) <> bytes
  end

  @spec decode_fields(binary()) :: [field()]
  def decode_fields(bin) when is_binary(bin) do
    do_decode_fields(bin, [])
  end

  defp do_decode_fields(<<>>, acc), do: Enum.reverse(acc)

  defp do_decode_fields(bin, acc) do
    {tag, rest} = Varint.decode_u64(bin)
    field_no = div(tag, 8)
    wire = rem(tag, 8)

    case wire do
      @wire_varint ->
        {v, rest2} = Varint.decode_u64(rest)
        do_decode_fields(rest2, [{field_no, wire, v} | acc])

      @wire_len ->
        {len, rest2} = Varint.decode_u64(rest)
        if byte_size(rest2) < len, do: raise(ArgumentError, "truncated length-delimited field")
        <<data::binary-size(len), rest3::binary>> = rest2
        do_decode_fields(rest3, [{field_no, wire, data} | acc])

      other ->
        raise ArgumentError, "unsupported protobuf wire type #{other}"
    end
  end
end
