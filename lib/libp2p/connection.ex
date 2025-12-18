defmodule Libp2p.Connection do
  @moduledoc """
  One libp2p connection process.

  Owns:
  - TCP socket
  - Noise secure channel state (`Libp2p.SecureConn`)
  - Yamux session state (`Libp2p.Yamux.Session`)

  Exposes basic stream send/recv primitives used by higher-level protocol handlers.
  """

  use GenServer

  alias Libp2p.{ConnUpgrade, SecureConn}
  alias Libp2p.Transport.Tcp
  alias Libp2p.Yamux.Session

  @type t :: pid()

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc "Block until the connection has completed the upgrade pipeline."
  @spec await_ready(t(), timeout()) :: :ok | {:error, term()}
  def await_ready(conn, timeout \\ 20_000) do
    GenServer.call(conn, :await_ready, timeout)
  end

  @doc "Open a new outbound yamux stream."
  @spec open_stream(t()) :: {:ok, non_neg_integer()} | {:error, term()}
  def open_stream(conn) do
    try do
      GenServer.call(conn, :open_stream)
    catch
      :exit, {:timeout, _} -> {:error, :timeout}
      :exit, :timeout -> {:error, :timeout}
      :exit, {:noproc, _} -> {:error, :noproc}
      :exit, :noproc -> {:error, :noproc}
    end
  end

  @doc "Return the remote peer id (from Noise) once ready."
  @spec remote_peer_id(t()) :: {:ok, binary()} | {:error, term()}
  def remote_peer_id(conn) do
    GenServer.call(conn, :remote_peer_id)
  end

  @spec peer_store(t()) :: term()
  def peer_store(conn) do
    GenServer.call(conn, :peer_store)
  end

  @doc "Send bytes on a yamux stream."
  @spec stream_send(t(), non_neg_integer(), binary()) :: :ok | {:error, term()}
  def stream_send(conn, stream_id, data) when is_integer(stream_id) and is_binary(data) do
    try do
      GenServer.call(conn, {:stream_send, stream_id, data})
    catch
      :exit, {:timeout, _} -> {:error, :timeout}
      :exit, :timeout -> {:error, :timeout}
      :exit, {:noproc, _} -> {:error, :noproc}
      :exit, :noproc -> {:error, :noproc}
    end
  end

  @doc "Receive bytes for a yamux stream (may return partial data)."
  @spec stream_recv(t(), non_neg_integer(), timeout()) :: {:ok, binary()} | {:error, term()}
  def stream_recv(conn, stream_id, timeout \\ 5_000) when is_integer(stream_id) do
    try do
      GenServer.call(conn, {:stream_recv, stream_id}, timeout)
    catch
      :exit, {:timeout, _} -> {:error, :timeout}
      :exit, :timeout -> {:error, :timeout}
      :exit, {:noproc, _} -> {:error, :noproc}
      :exit, :noproc -> {:error, :noproc}
    end
  end

  @doc "Close (FIN) a yamux stream."
  @spec stream_close(t(), non_neg_integer()) :: :ok | {:error, term()}
  def stream_close(conn, stream_id) when is_integer(stream_id) do
    GenServer.call(conn, {:stream_close, stream_id})
  end

  @doc "Set the process that will receive stream events."
  @spec set_stream_handler(t(), non_neg_integer(), pid()) :: :ok
  def set_stream_handler(conn, stream_id, pid) do
    GenServer.call(conn, {:set_stream_handler, stream_id, pid})
  end

  @impl true
  def init(opts) do
    st = %{
      swarm: Keyword.fetch!(opts, :swarm),
      socket: Keyword.fetch!(opts, :socket),
      direction: Keyword.fetch!(opts, :direction),
      identity: Keyword.fetch!(opts, :identity),
      peer_store: Keyword.fetch!(opts, :peer_store),
      secure: nil,
      yamux: nil,
      streams: %{},
      ready_waiters: [],
      started?: false,
      remote_peer_id: nil
    }

    # Swarm will transfer socket ownership then send :start_upgrade.
    {:ok, st}
  end

  @impl true
  def handle_continue(:upgrade, st) do
    upgrade =
      case st.direction do
        :inbound -> ConnUpgrade.upgrade_inbound(st.socket, st.identity, timeout: 30_000)
        :outbound -> ConnUpgrade.upgrade_outbound(st.socket, st.identity, timeout: 30_000)
      end

    case upgrade do
      {:ok, %SecureConn{} = secure, %Session{} = yamux, remote_peer_id} ->
        :ok = :inet.setopts(st.socket, active: :once)
        st = %{st | secure: secure, yamux: yamux}
        st = %{st | remote_peer_id: remote_peer_id}
        send(st.swarm, {:connection_ready, self(), remote_peer_id})
        Enum.each(st.ready_waiters, fn from -> GenServer.reply(from, :ok) end)
        {:noreply, %{st | ready_waiters: []}}

      {:error, reason} ->
        _ = Tcp.close(st.socket)
        Enum.each(st.ready_waiters, fn from -> GenServer.reply(from, {:error, reason}) end)
        {:stop, reason, st}
    end
  end

  @impl true
  def handle_call(:await_ready, from, %{secure: nil} = st) do
    {:noreply, %{st | ready_waiters: [from | st.ready_waiters]}}
  end

  def handle_call(:await_ready, _from, st) do
    {:reply, :ok, st}
  end

  def handle_call(:remote_peer_id, _from, %{remote_peer_id: nil} = st), do: {:reply, {:error, :not_ready}, st}
  def handle_call(:remote_peer_id, _from, st), do: {:reply, {:ok, st.remote_peer_id}, st}

  def handle_call(:peer_store, _from, st), do: {:reply, st.peer_store, st}

  def handle_call(:__local_identity__, _from, st), do: {:reply, st.identity, st}

  def handle_call(:open_stream, _from, %{secure: nil} = st), do: {:reply, {:error, :not_ready}, st}

  def handle_call(:open_stream, _from, st) do
    {id, out, yamux2} = Session.open_stream(st.yamux)

    case SecureConn.send(st.secure, out) do
      {:ok, secure2} ->
        st = %{st | secure: secure2, yamux: yamux2}
        st = ensure_stream(st, id)
        {:reply, {:ok, id}, st}

      {:error, reason} ->
        {:reply, {:error, reason}, st}
    end
  end

  def handle_call({:open_stream, initial_data}, _from, st) do
    {id, out, yamux2} = Session.open_stream_with_data(st.yamux, initial_data)

    case SecureConn.send(st.secure, out) do
      {:ok, secure2} ->
        st = %{st | secure: secure2, yamux: yamux2}
        st = ensure_stream(st, id)
        {:reply, {:ok, id}, st}

      {:error, reason} ->
        {:reply, {:error, reason}, st}
    end
  end

  def handle_call({:stream_send, id, data}, _from, st) do
    st = ensure_stream(st, id)
    {out, yamux2} = Session.send_data(st.yamux, id, data)

    case SecureConn.send(st.secure, out) do
      {:ok, secure2} -> {:reply, :ok, %{st | secure: secure2, yamux: yamux2}}
      {:error, reason} -> {:reply, {:error, reason}, st}
    end
  end

  def handle_call({:send_stream, id, data}, from, st) do
    handle_call({:stream_send, id, data}, from, st)
  end

  def handle_call({:stream_close, id}, _from, st) do
    st = ensure_stream(st, id)
    {out, yamux2} = Session.close_stream(st.yamux, id)

    case SecureConn.send(st.secure, out) do
      {:ok, secure2} ->
        st = %{st | secure: secure2, yamux: yamux2}
        {:reply, :ok, mark_stream_closed(st, id)}

      {:error, reason} ->
        {:reply, {:error, reason}, st}
    end
  end

  def handle_call({:close_stream, id}, from, st) do
    handle_call({:stream_close, id}, from, st)
  end

  def handle_call({:stream_recv, id}, from, st) do
    st = ensure_stream(st, id)
    s = st.streams[id]

    cond do
      s.closed? and s.buf == <<>> ->
        {:reply, {:error, :closed}, st}

      s.buf != <<>> ->
        {:reply, {:ok, s.buf}, put_stream(st, id, %{s | buf: <<>>})}

      true ->
        {:noreply, put_stream(st, id, %{s | waiters: [from | s.waiters]})}
    end
  end

  def handle_call({:set_stream_handler, id, pid}, _from, st) do
    st = ensure_stream(st, id)
    s = st.streams[id]

    # If buffer has data, push it immediately
    s =
      if s.buf != <<>> do
        send(pid, {:libp2p, :stream_data, self(), id, s.buf})
        %{s | buf: <<>>}
      else
        s
      end

    {:reply, :ok, put_stream(st, id, %{s | owner: pid})}
  end

  @impl true
  def handle_info({:tcp, sock, data}, %{socket: sock, secure: %SecureConn{} = secure, yamux: %Session{} = yamux} = st) do
    :ok = :inet.setopts(sock, active: :once)

    secure = SecureConn.ingest(secure, data)
    {msgs, secure} = SecureConn.drain(secure)

    {st, secure, yamux} =
      Enum.reduce(msgs, {st, secure, yamux}, fn pt, {st_acc, sec_acc, yamux_acc} ->
        {events, out, yamux2} = Session.feed(yamux_acc, pt)
        st2 = handle_yamux_events(st_acc, events)

        sec2 =
          if out == <<>> do
            sec_acc
          else
            case SecureConn.send(sec_acc, out) do
              {:ok, sec_ok} -> sec_ok
              {:error, _} -> sec_acc
            end
          end

        {st2, sec2, yamux2}
      end)

    {:noreply, %{st | secure: secure, yamux: yamux}}
  end

  def handle_info({:tcp_closed, sock}, %{socket: sock} = st) do
    {:stop, :tcp_closed, st}
  end

  def handle_info(:start_upgrade, %{started?: false} = st) do
    {:noreply, %{st | started?: true}, {:continue, :upgrade}}
  end

  def handle_info(:start_upgrade, st) do
    {:noreply, st}
  end

  def handle_info(_msg, st), do: {:noreply, st}



# ...

  def handle_call({:set_stream_handler, id, pid}, _from, st) do
    st = ensure_stream(st, id)
    s = st.streams[id]

    # If buffer has data, push it immediately
    s =
      if s.buf != <<>> do
        send(pid, {:libp2p, :stream_data, self(), id, s.buf})
        %{s | buf: <<>>}
      else
        s
      end

    put_stream(st, id, %{s | owner: pid})
    {:reply, :ok, st}
  end

# ...

  defp ensure_stream(st, id) do
    if Map.has_key?(st.streams, id) do
      st
    else
      put_stream(st, id, %{buf: <<>>, waiters: [], closed?: false, owner: nil})
    end
  end

  defp put_stream(st, id, stream_state) do
    %{st | streams: Map.put(st.streams, id, stream_state)}
  end

  defp mark_stream_closed(st, id) do
    # Notify owner
    s = Map.get(st.streams, id, %{buf: <<>>, waiters: [], closed?: true, owner: nil})
    if is_pid(s.owner), do: send(s.owner, {:libp2p, :stream_closed, self(), id})
    put_stream(st, id, %{s | closed?: true})
  end

  defp handle_yamux_events(st, events) do
    Enum.reduce(events, st, fn
      {:stream_open, id}, st_acc ->
        st_acc = ensure_stream(st_acc, id)
        send(st_acc.swarm, {:inbound_stream, self(), id})
        st_acc

      {:stream_data, id, data}, st_acc ->
        st_acc = ensure_stream(st_acc, id)
        s = st_acc.streams[id]

        if is_pid(s.owner) do
             send(s.owner, {:libp2p, :stream_data, self(), id, data})
             st_acc
        else
            s = %{s | buf: s.buf <> data}
            {st_acc, s} = maybe_wake_waiter(st_acc, id, s)
            put_stream(st_acc, id, s)
        end

      {:stream_close, id}, st_acc ->
        st_acc = ensure_stream(st_acc, id)
        s = %{st_acc.streams[id] | closed?: true}
        if is_pid(s.owner), do: send(s.owner, {:libp2p, :stream_closed, self(), id})
        {st_acc, s} = maybe_wake_waiter(st_acc, id, s)
        put_stream(st_acc, id, s)

      {:stream_reset, id}, st_acc ->
        st_acc = ensure_stream(st_acc, id)
        s = %{st_acc.streams[id] | closed?: true}
        if is_pid(s.owner), do: send(s.owner, {:libp2p, :stream_closed, self(), id})
        {st_acc, s} = maybe_wake_waiter(st_acc, id, s)
        put_stream(st_acc, id, s)
    end)
  end

  defp maybe_wake_waiter(st, _id, s) do
    case s.waiters do
      [] ->
        {st, s}

      [from | rest] ->
        if s.buf != <<>> do
          GenServer.reply(from, {:ok, s.buf})
          {st, %{s | buf: <<>>, waiters: rest}}
        else
          if s.closed? do
            GenServer.reply(from, {:error, :closed})
            {st, %{s | waiters: rest}}
          else
            {st, s}
          end
        end
    end
  end
end
