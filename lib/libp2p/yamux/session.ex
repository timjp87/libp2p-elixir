defmodule Libp2p.Yamux.Session do
  @moduledoc """
  Minimal yamux session state machine.

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
    id = st.next_stream_id
    st = %{st | next_stream_id: id + 2, streams: Map.put(st.streams, id, stream_state(:outbound))}

    # Open stream by sending a data frame with SYN (empty payload).
    frame = %Frame{type: :data, flags: @syn, stream_id: id, data: <<>>}
    {id, Frame.encode(frame) |> IO.iodata_to_binary(), st}
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
    frame = %Frame{type: :data, flags: @syn, stream_id: id, data: data}
    {id, Frame.encode(frame) |> IO.iodata_to_binary(), st}
  end

  @doc """
  Send data on an open stream. Returns `{out_bytes, st2}`.
  """
  @spec send_data(t(), non_neg_integer(), binary()) :: {binary(), t()}
  def send_data(%__MODULE__{} = st, stream_id, data) when is_integer(stream_id) and is_binary(data) do
    _ = Map.fetch!(st.streams, stream_id)
    frame = %Frame{type: :data, flags: 0, stream_id: stream_id, data: data}
    {Frame.encode(frame) |> IO.iodata_to_binary(), st}
  end

  @doc """
  Half-close (FIN) a stream. Returns `{out_bytes, st2}`.
  """
  @spec close_stream(t(), non_neg_integer()) :: {binary(), t()}
  def close_stream(%__MODULE__{} = st, stream_id) when is_integer(stream_id) do
    case Map.get(st.streams, stream_id) do
      nil ->
        {<<>>, st}

      s ->
        st = %{st | streams: Map.put(st.streams, stream_id, Map.put(s, :local_closed, true))}
        frame = %Frame{type: :data, flags: @fin, stream_id: stream_id, data: <<>>}
        {Frame.encode(frame) |> IO.iodata_to_binary(), maybe_gc(stream_id, st)}
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
        {events, [Frame.encode(ack) | out], st}

      band(flags, @ack) != 0 ->
        s = Map.get(st.streams, id, %{})
        st = %{st | streams: Map.put(st.streams, id, Map.put(s, :acked, true))}
        # ACK may be combined with a DATA frame (including payload and/or FIN).
        events = if f.data != <<>>, do: [{:stream_data, id, f.data} | events], else: events
        st2 = maybe_handle_fin(st, id, flags)
        events = if band(flags, @fin) != 0, do: [{:stream_close, id} | events], else: events
        {events, out, st2}

      true ->
        events = if f.data != <<>>, do: [{:stream_data, id, f.data} | events], else: events
        st2 = maybe_handle_fin(st, id, flags)
        events = if band(flags, @fin) != 0, do: [{:stream_close, id} | events], else: events
        {events, out, st2}
    end
  end

  defp handle_frame(st, %Frame{type: :window_update} = f, events, out) do
    id = f.stream_id
    flags = f.flags || 0

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

    if band(flags, @ack) != 0 do
      s = Map.get(st.streams, id, %{})
      st = %{st | streams: Map.put(st.streams, id, Map.put(s, :acked, true))}
      {events, out, st}
    else
      {events, out, st}
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
      remote_closed: false
    }
  end

  defp band(a, b), do: :erlang.band(a, b)
end
