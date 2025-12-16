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

  @initial_window 256 * 1024

  @type event ::
          {:stream_open, non_neg_integer()}
          | {:stream_data, non_neg_integer(), binary()}
          | {:stream_close, non_neg_integer()}
          | {:stream_reset, non_neg_integer()}

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
    s = Map.fetch!(st.streams, stream_id)
    st = %{st | streams: Map.put(st.streams, stream_id, Map.put(s, :local_closed, true))}
    frame = %Frame{type: :data, flags: @fin, stream_id: stream_id, data: <<>>}
    {Frame.encode(frame) |> IO.iodata_to_binary(), maybe_gc(stream_id, st)}
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
        # ACK it (can be Data or WindowUpdate; we use WindowUpdate with ACK and initial window)
        ack = %Frame{type: :window_update, flags: @ack, stream_id: id, length: @initial_window}
        events = [{:stream_open, id} | events]
        events = if f.data != <<>>, do: [{:stream_data, id, f.data} | events], else: events
        {events, [Frame.encode(ack) | out], st}

      band(flags, @ack) != 0 ->
        s = Map.get(st.streams, id, %{})
        st = %{st | streams: Map.put(st.streams, id, Map.put(s, :acked, true))}
        {events, out, st}

      true ->
        events = if f.data != <<>>, do: [{:stream_data, id, f.data} | events], else: events

        {events, out, maybe_handle_fin(st, id, flags)}
    end
  end

  defp handle_frame(st, %Frame{type: :window_update} = f, events, out) do
    id = f.stream_id
    flags = f.flags || 0

    st =
      if Map.has_key?(st.streams, id) == false and band(flags, @syn) != 0 do
        %{st | streams: Map.put(st.streams, id, stream_state(:inbound))}
      else
        st
      end

    if band(flags, @ack) != 0 do
      s = Map.get(st.streams, id, %{})
      st = %{st | streams: Map.put(st.streams, id, Map.put(s, :acked, true))}
      {events, out, st}
    else
      {events, out, st}
    end
  end

  defp handle_frame(st, %Frame{type: :ping}, events, out), do: {events, out, st}
  defp handle_frame(st, %Frame{type: :go_away}, events, out), do: {events, out, st}

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
