defmodule Libp2p.Yamux.Frame do
  @moduledoc """
  Yamux frame encode/decode per `third_party/libp2p_specs/yamux/README.md`.

  Header (12 bytes, big-endian / network order):
  - Version (u8)  (always 0)
  - Type (u8)     (data=0, window_update=1, ping=2, go_away=3)
  - Flags (u16)
  - StreamID (u32)
  - Length (u32)

  For `:data` frames, `Length` is the number of bytes following the header.
  For all other frame types, `Length` is an in-header value (no payload bytes).
  """

  @header_len 12

  @type type :: :data | :window_update | :ping | :go_away

  @type t :: %__MODULE__{
          type: type(),
          flags: non_neg_integer(),
          stream_id: non_neg_integer(),
          length: non_neg_integer(),
          data: binary()
        }

  defstruct [:type, :flags, :stream_id, :length, data: <<>>]

  @spec encode(t()) :: iodata()
  def encode(%__MODULE__{} = f) do
    {type_byte, payload} =
      case f.type do
        :data -> {0x0, f.data}
        :window_update -> {0x1, <<>>}
        :ping -> {0x2, <<>>}
        :go_away -> {0x3, <<>>}
      end

    ver = 0
    flags = f.flags || 0
    stream_id = f.stream_id || 0

    len =
      case f.type do
        :data -> byte_size(payload)
        _ -> f.length || 0
      end

    [
      <<ver::unsigned-big-integer-size(8), type_byte::unsigned-big-integer-size(8), flags::unsigned-big-integer-size(16),
        stream_id::unsigned-big-integer-size(32), len::unsigned-big-integer-size(32)>>,
      payload
    ]
  end

  @doc """
  Decode a single yamux frame from `bin`.
  Returns `{frame, rest}` or `:more` if incomplete.
  """
  @spec decode_one(binary()) :: {t(), binary()} | :more
  def decode_one(bin) when is_binary(bin) do
    if byte_size(bin) < @header_len do
      :more
    else
      <<ver::unsigned-big-integer-size(8), type_byte::unsigned-big-integer-size(8), flags::unsigned-big-integer-size(16),
        stream_id::unsigned-big-integer-size(32), len::unsigned-big-integer-size(32), rest::binary>> = bin

      if ver != 0 do
        raise ArgumentError, "unsupported yamux version #{ver}"
      end

      type =
        case type_byte do
          0x0 -> :data
          0x1 -> :window_update
          0x2 -> :ping
          0x3 -> :go_away
          other -> raise ArgumentError, "unknown yamux frame type 0x#{Integer.to_string(other, 16)}"
        end

      case type do
        :data ->
          if byte_size(rest) < len do
            :more
          else
            <<payload::binary-size(len), tail::binary>> = rest
            {%__MODULE__{type: :data, flags: flags, stream_id: stream_id, length: len, data: payload}, tail}
          end

        _ ->
          {%__MODULE__{type: type, flags: flags, stream_id: stream_id, length: len, data: <<>>}, rest}
      end
    end
  end

  @spec decode_frames(binary(), [t()]) :: {[t()], binary()}
  def decode_frames(bin, acc \\ []) when is_binary(bin) and is_list(acc) do
    case decode_one(bin) do
      :more ->
        {Enum.reverse(acc), bin}

      {frame, rest} ->
        decode_frames(rest, [frame | acc])
    end
  end
end
