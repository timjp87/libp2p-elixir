defmodule Libp2p.MultistreamSelect do
  @moduledoc """
  Multistream-select 1.0 negotiation helpers.

  Used to negotiate:
  - connection-level protocols (security, muxer) and
  - stream-level protocols (app protocols, e.g. eth2 req/resp).
  """

  alias Libp2p.Varint

  @mss "/multistream/1.0.0"
  @na "na"

  @type role :: :initiator | :responder

  @type state :: %{
          role: role(),
          buf: binary(),
          # initiator:
          proposals: [binary()],
          # negotiated:
          selected: nil | binary(),
          # whether we've sent/received the multistream header
          sent_mss?: boolean(),
          got_mss?: boolean()
        }

  @spec new_initiator([binary()]) :: state()
  def new_initiator(proposals) when is_list(proposals) do
    %{role: :initiator, buf: <<>>, proposals: proposals, selected: nil, sent_mss?: false, got_mss?: false}
  end

  @spec new_responder() :: state()
  def new_responder do
    %{role: :responder, buf: <<>>, proposals: [], selected: nil, sent_mss?: false, got_mss?: false}
  end

  @spec multistream_id() :: binary()
  def multistream_id, do: @mss

  @doc """
  Encode a multistream-select message (uvarint length prefix + utf8 + `\\n`).
  """
  @spec encode_message(binary()) :: binary()
  def encode_message(msg) when is_binary(msg) do
    payload = msg <> "\n"
    Varint.encode_u64(byte_size(payload)) <> payload
  end

  @doc """
  Decode a single message. Returns `{msg, rest}` or `:more`.

  Returned `msg` excludes the trailing `\\n`.
  """
  @spec decode_message(binary()) :: {binary(), binary()} | :more
  def decode_message(bin) when is_binary(bin) do
    try do
      {len, rest} = Varint.decode_u64(bin)
      if byte_size(rest) < len, do: :more, else: decode_message_len(rest, len)
    rescue
      ArgumentError ->
        :more
    end
  end

  defp decode_message_len(rest, len) do
    <<payload::binary-size(len), tail::binary>> = rest

    if payload == <<>> or :binary.last(payload) != 0x0A do
      raise ArgumentError, "invalid multistream message (missing newline)"
    end

    {binary_part(payload, 0, byte_size(payload) - 1), tail}
  end

  @doc """
  Produce bytes that should be written immediately when starting negotiation.
  """
  @spec start(state()) :: {binary(), state()}
  def start(%{sent_mss?: false} = st) do
    {encode_message(@mss), %{st | sent_mss?: true}}
  end

  def start(%{sent_mss?: true} = st), do: {<<>>, st}

  @doc """
  Feed inbound bytes. Returns `{events, out_bytes, st2}`.

  Events:
  - `{:selected, protocol_id}` when negotiation completes successfully.
  - `{:error, reason}` for protocol violations.
  """
  @spec feed(state(), binary(), MapSet.t(binary())) :: {[term()], binary(), state()}
  def feed(st, bytes, supported_protocols) when is_binary(bytes) do
    st = %{st | buf: st.buf <> bytes}
    do_feed(st, supported_protocols, [], [])
  end

  defp do_feed(st, supported, events, out) do
    case decode_message(st.buf) do
      :more ->
        {Enum.reverse(events), IO.iodata_to_binary(Enum.reverse(out)), st}

      {msg, rest} ->
        st = %{st | buf: rest}
        {events2, out2, st2} = handle_msg(st, supported, msg, events, out)
        do_feed(st2, supported, events2, out2)
    end
  end

  defp handle_msg(%{got_mss?: false} = st, _supported, msg, events, out) do
    if msg != @mss do
      {[{:error, {:expected_multistream, msg}} | events], out, st}
    else
      st = %{st | got_mss?: true}
      {out, st} = maybe_initiator_send_proposal(out, st)
      {events, out, st}
    end
  end

  defp handle_msg(%{role: :initiator, selected: nil} = st, _supported, msg, events, out) do
    cond do
      msg == @na ->
        case st.proposals do
          [] ->
            {[{:error, :no_common_protocol} | events], out, st}

          [_failed | rest] ->
            st = %{st | proposals: rest}
            {out, st} = maybe_initiator_send_proposal(out, st)
            {events, out, st}
        end

      msg == hd_or_nil(st.proposals) ->
        st = %{st | selected: msg}
        {[{:selected, msg} | events], out, st}

      true ->
        {[{:error, {:unexpected_response, msg}} | events], out, st}
    end
  end

  defp handle_msg(%{role: :responder, selected: nil} = st, supported, msg, events, out) do
    if MapSet.member?(supported, msg) do
      st = %{st | selected: msg}
      out = [encode_message(msg) | out]
      {[{:selected, msg} | events], out, st}
    else
      out = [encode_message(@na) | out]
      {events, out, st}
    end
  end

  defp handle_msg(st, _supported, _msg, events, out), do: {events, out, st}

  defp maybe_initiator_send_proposal(out, %{role: :initiator, got_mss?: true} = st) do
    case st.proposals do
      [] ->
        {out, st}

      [p | _] ->
        out = [encode_message(p) | out]
        {out, st}
    end
  end

  defp maybe_initiator_send_proposal(out, st), do: {out, st}

  defp hd_or_nil([]), do: nil
  defp hd_or_nil([h | _]), do: h
end
