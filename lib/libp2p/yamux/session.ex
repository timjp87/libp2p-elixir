defmodule Libp2p.Yamux.Session do
  @moduledoc """
  Manages a Yamux multiplexing session.

  Yamux allows multiple concurrent streams to be multiplexed over a single reliable connection.
  This module implements the session management, frame parsing, and flow control.

  ## Framing

  Every message in Yamux is prefixed with a 12-byte header containing:
  - **Version**: (Always 0).
  - **Type**: The message type (Data, WindowUpdate, Ping, GoAway).
  - **Flags**: Modifiers like SYN (new stream), ACK (accept stream), FIN (close stream), RST (reset).
  - **StreamID**: The identifier for the logical stream (0 is reserved for the session).
  - **Length**: Payload length or control value.

  ## Flow Control

  Yamux uses a reliable credit-based flow control system to prevent fast senders from overwhelming
  receivers.
  - Each stream starts with a receiving window of 256KB.
  - As data is consumed, `WindowUpdate` frames are sent to the peer to grant more sending credit.
  - If the window is exhausted, the sender must pause until an update is received.

  ## Stream IDs

  To avoid collisions, clients (initiators) use odd stream IDs, and servers (listeners) use even stream IDs.

  This is a pure(ish) state machine that:
  - consumes inbound bytes -> frames -> events
  - produces outbound frames for stream open/ack/data/close

  It intentionally implements only what we need to bootstrap higher layers.
  """

  alias Libp2p.Yamux.Frame

  # frame types
  @type t :: %__MODULE__{
          role: :client | :server,
          next_stream_id: non_neg_integer(),
          buffer: binary(),
          streams: %{non_neg_integer() => map()}
        }

  defstruct [:role, :next_stream_id, buffer: <<>>, streams: %{}]

  # flags (u16)
  @syn 0x1
  @ack 0x2
  @fin 0x4
  @rst 0x8
  @initial_window_size 256 * 1024

  @type event ::
          {:stream_open, non_neg_integer()}
          | {:stream_data, non_neg_integer(), binary()}
          | {:stream_close, non_neg_integer()}
          | {:stream_reset, non_neg_integer()}
          | {:go_away, non_neg_integer()}

  @spec new(:client | :server) :: t()
  def new(role) when role in [:client, :server] do
    start_id = if role == :client, do: 1, else: 2
    %__MODULE__{role: role, next_stream_id: start_id}
  end

  @doc """
  Open an outbound stream. Returns `{stream_id, out_bytes, session2}`.
  """
  @spec open_stream(t()) :: {non_neg_integer(), binary(), t()}
  def open_stream(%__MODULE__{} = st) do
    open_stream_with_data(st, <<>>)
  end

  @doc """
  Open an outbound stream and send initial data in the SYN frame.

  Some peers appear to be strict about receiving the first payload alongside SYN.
  Returns `{stream_id, out_bytes, session2}`.
  """
  @spec open_stream_with_data(t(), binary()) :: {non_neg_integer(), binary(), t()}
  def open_stream_with_data(%__MODULE__{} = st, data) when is_binary(data) do
    id = st.next_stream_id
    st = %{st | next_stream_id: id + 2, streams: Map.put(st.streams, id, stream_state(:outbound))}
    {out, st} = send_new_stream_data(st, id, data)
    {id, out, st}
  end

  @doc """
  Send data on an open stream. Returns `{out_bytes, st2}`.
  """
  @spec send_data(t(), non_neg_integer(), binary()) :: {binary(), t()}
  def send_data(%__MODULE__{} = st, stream_id, data)
      when is_integer(stream_id) and is_binary(data) do
    _ = Map.fetch!(st.streams, stream_id)

    st = append_pending_send(st, stream_id, data)
    {out, st} = flush_pending_send_bytes(st, stream_id)
    {out, st}
  end

  @doc """
  Half-close (FIN) a stream. Returns `{out_bytes, st2}`.
  """
  @spec close_stream(t(), non_neg_integer()) :: {binary(), t()}
  def close_stream(%__MODULE__{} = st, stream_id) when is_integer(stream_id) do
    case Map.get(st.streams, stream_id) do
      nil ->
        {<<>>, st}

      stream ->
        stream = Map.put(stream, :pending_fin, true)
        st = %{st | streams: Map.put(st.streams, stream_id, stream)}
        {out, st} = flush_pending_send_bytes(st, stream_id)
        {out, st}
    end
  end

  @doc """
  Hard reset a stream. Returns `{out_bytes, st2}`.
  """
  @spec reset_stream(t(), non_neg_integer()) :: {binary(), t()}
  def reset_stream(%__MODULE__{} = st, stream_id) when is_integer(stream_id) do
    st = %{st | streams: Map.delete(st.streams, stream_id)}
    frame = %Frame{type: :data, flags: @rst, stream_id: stream_id, data: <<>>}
    {Frame.encode(frame) |> IO.iodata_to_binary(), st}
  end

  @doc """
  Feed inbound bytes. Returns `{events, out_bytes, st2}`.
  """
  @spec feed(t(), binary()) :: {[event()], binary(), t()}
  def feed(%__MODULE__{} = st, bytes) when is_binary(bytes) do
    st = %{st | buffer: st.buffer <> bytes}
    {frames, buf} = Frame.decode_frames(st.buffer)
    st = %{st | buffer: buf}
    {events, out_frames, st2} = handle_frames(st, frames, [], [])
    {Enum.reverse(events), out_frames |> Enum.reverse() |> IO.iodata_to_binary(), st2}
  end

  defp handle_frames(st, [], events, out), do: {events, out, st}

  defp handle_frames(st, [f | rest], events, out) do
    {events2, out2, st2} = handle_frame(st, f, events, out)
    handle_frames(st2, rest, events2, out2)
  end

  defp handle_frame(st, %Frame{type: :data} = f, events, out) do
    id = f.stream_id
    flags = f.flags || 0

    cond do
      band(flags, @rst) != 0 ->
        st = %{st | streams: Map.delete(st.streams, id)}
        {[{:stream_reset, id} | events], out, st}

      Map.has_key?(st.streams, id) == false and band(flags, @syn) != 0 ->
        # new inbound stream
        st = %{st | streams: Map.put(st.streams, id, stream_state(:inbound))}
        # ACK it.
        #
        # The yamux spec allows replying with either a DATA or WINDOW_UPDATE frame carrying ACK.
        # In practice, some implementations appear to be stricter about the ACK frame type.
        # Use an empty DATA+ACK here for broad interop.
        ack = %Frame{type: :data, flags: @ack, stream_id: id, data: <<>>}
        events = [{:stream_open, id} | events]
        events = if f.data != <<>>, do: [{:stream_data, id, f.data} | events], else: events
        out = [Frame.encode(ack) | out]
        out = maybe_replenish_window(f, out)
        st = maybe_handle_fin(st, id, flags)
        events = if band(flags, @fin) != 0, do: [{:stream_close, id} | events], else: events
        {events, out, st}

      band(flags, @ack) != 0 ->
        s = Map.get(st.streams, id, %{})
        st = %{st | streams: Map.put(st.streams, id, Map.put(s, :acked, true))}
        # ACK may be combined with a DATA frame (including payload and/or FIN).
        events = if f.data != <<>>, do: [{:stream_data, id, f.data} | events], else: events
        out = maybe_replenish_window(f, out)
        st2 = maybe_handle_fin(st, id, flags)
        events = if band(flags, @fin) != 0, do: [{:stream_close, id} | events], else: events
        {events, out, st2}

      true ->
        events = if f.data != <<>>, do: [{:stream_data, id, f.data} | events], else: events
        out = maybe_replenish_window(f, out)
        st2 = maybe_handle_fin(st, id, flags)
        events = if band(flags, @fin) != 0, do: [{:stream_close, id} | events], else: events
        {events, out, st2}
    end
  end

  defp handle_frame(st, %Frame{type: :window_update} = f, events, out) do
    id = f.stream_id
    flags = f.flags || 0

    cond do
      band(flags, @rst) != 0 ->
        st = %{st | streams: Map.delete(st.streams, id)}
        {[{:stream_reset, id} | events], out, st}

      true ->
        {events, out, st} =
          if Map.has_key?(st.streams, id) == false and band(flags, @syn) != 0 do
            st = %{st | streams: Map.put(st.streams, id, stream_state(:inbound))}
            # See comment above: ACK only, no window delta.
            ack = %Frame{type: :window_update, flags: @ack, stream_id: id, length: 0}
            events = [{:stream_open, id} | events]
            {events, [Frame.encode(ack) | out], st}
          else
            {events, out, st}
          end

        st =
          st
          |> maybe_mark_acked(id, flags)
          |> maybe_add_send_window(id, f.length)

        st = maybe_handle_fin(st, id, flags)
        events = if band(flags, @fin) != 0, do: [{:stream_close, id} | events], else: events
        {flushed, st} = flush_pending_send(st, id, out)
        {events, flushed, st}
    end
  end

  defp handle_frame(st, %Frame{type: :ping} = f, events, out) do
    # Yamux ping: reply to SYN with ACK and same "length" (nonce).
    flags = f.flags || 0

    if band(flags, @syn) != 0 and band(flags, @ack) == 0 do
      ack = %Frame{type: :ping, flags: @ack, stream_id: 0, length: f.length}
      {events, [Frame.encode(ack) | out], st}
    else
      {events, out, st}
    end
  end

  defp handle_frame(st, %Frame{type: :go_away} = f, events, out) do
    # Surface GOAWAY for diagnostics; callers may choose to close the connection.
    {[{:go_away, f.length} | events], out, st}
  end

  defp send_new_stream_data(st, stream_id, <<>>) do
    frame = %Frame{type: :data, flags: @syn, stream_id: stream_id, data: <<>>}
    {Frame.encode(frame) |> IO.iodata_to_binary(), st}
  end

  defp send_new_stream_data(st, stream_id, data) do
    case Map.fetch!(st.streams, stream_id) do
      %{send_window: window} = stream when window > 0 ->
        send_len = min(byte_size(data), window)
        <<chunk::binary-size(send_len), rest::binary>> = data

        stream =
          stream
          |> Map.put(:send_window, window - send_len)
          |> Map.put(:pending_send, rest)

        st = %{st | streams: Map.put(st.streams, stream_id, stream)}
        frame = %Frame{type: :data, flags: @syn, stream_id: stream_id, data: chunk}
        {Frame.encode(frame) |> IO.iodata_to_binary(), st}

      stream ->
        stream = Map.put(stream, :pending_send, data)
        st = %{st | streams: Map.put(st.streams, stream_id, stream)}
        frame = %Frame{type: :data, flags: @syn, stream_id: stream_id, data: <<>>}
        {Frame.encode(frame) |> IO.iodata_to_binary(), st}
    end
  end

  defp append_pending_send(st, stream_id, data) do
    stream = Map.fetch!(st.streams, stream_id)
    pending = Map.get(stream, :pending_send, <<>>)
    stream = Map.put(stream, :pending_send, pending <> data)
    %{st | streams: Map.put(st.streams, stream_id, stream)}
  end

  defp flush_pending_send_bytes(st, stream_id) do
    {out, st} = flush_pending_send(st, stream_id, [])
    {out |> Enum.reverse() |> IO.iodata_to_binary(), st}
  end

  defp flush_pending_send(st, stream_id, out) do
    case Map.get(st.streams, stream_id) do
      nil ->
        {out, st}

      %{pending_send: pending, send_window: window} = stream
      when is_binary(pending) and byte_size(pending) > 0 and is_integer(window) and window > 0 ->
        send_len = min(byte_size(pending), window)
        <<chunk::binary-size(send_len), rest::binary>> = pending

        stream =
          stream
          |> Map.put(:pending_send, rest)
          |> Map.put(:send_window, window - send_len)

        st = %{st | streams: Map.put(st.streams, stream_id, stream)}
        frame = %Frame{type: :data, flags: 0, stream_id: stream_id, data: chunk}
        flush_pending_send(st, stream_id, [Frame.encode(frame) | out])

      %{pending_send: <<>>, pending_fin: true} = stream ->
        stream =
          stream
          |> Map.put(:pending_fin, false)
          |> Map.put(:local_closed, true)

        st = %{st | streams: Map.put(st.streams, stream_id, stream)}
        frame = %Frame{type: :data, flags: @fin, stream_id: stream_id, data: <<>>}
        st = maybe_gc(stream_id, st)
        {[Frame.encode(frame) | out], st}

      _stream ->
        {out, st}
    end
  end

  defp maybe_mark_acked(st, id, flags) do
    if band(flags, @ack) != 0 do
      s = Map.get(st.streams, id, %{})
      %{st | streams: Map.put(st.streams, id, Map.put(s, :acked, true))}
    else
      st
    end
  end

  defp maybe_add_send_window(st, id, delta) when is_integer(delta) and delta > 0 do
    case Map.get(st.streams, id) do
      nil ->
        st

      stream ->
        window = Map.get(stream, :send_window, @initial_window_size)
        stream = Map.put(stream, :send_window, window + delta)
        %{st | streams: Map.put(st.streams, id, stream)}
    end
  end

  defp maybe_add_send_window(st, _id, _delta), do: st

  defp maybe_handle_fin(st, id, flags) do
    if band(flags, @fin) != 0 do
      s = Map.get(st.streams, id, %{})
      st = %{st | streams: Map.put(st.streams, id, Map.put(s, :remote_closed, true))}
      st = maybe_gc(id, st)
      st
    else
      st
    end
  end

  # Yamux flow control:
  #
  # Many production implementations enforce a per-stream send window (commonly 256KB initial).
  # This session immediately credits back exactly what it receives, treating inbound bytes as
  # consumed when delivered to the application.
  defp maybe_replenish_window(%Frame{stream_id: id, data: data}, out)
       when is_binary(data) and byte_size(data) > 0 do
    update = %Frame{type: :window_update, flags: 0, stream_id: id, length: byte_size(data)}
    [Frame.encode(update) | out]
  end

  defp maybe_replenish_window(_frame, out), do: out

  defp maybe_gc(id, st) do
    s = Map.get(st.streams, id)

    if s != nil and Map.get(s, :local_closed, false) and Map.get(s, :remote_closed, false) do
      %{st | streams: Map.delete(st.streams, id)}
    else
      st
    end
  end

  defp stream_state(dir) do
    %{
      dir: dir,
      acked: dir == :inbound,
      local_closed: false,
      remote_closed: false,
      send_window: @initial_window_size,
      pending_send: <<>>,
      pending_fin: false
    }
  end

  defp band(a, b), do: :erlang.band(a, b)
end
