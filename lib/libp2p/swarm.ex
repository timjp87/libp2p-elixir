defmodule Libp2p.Swarm do
  @moduledoc """
  Minimal Swarm runtime for the libp2p subset we implement.

  Responsibilities:
  - start/stop TCP listeners
  - dial peers
  - supervise connections (each connection owns its socket + yamux session)
  - notify on inbound streams for protocol routing

  Protocol routing is implemented in later steps (Identify/Gossipsub/ReqResp).
  """

  use GenServer

  alias Libp2p.StreamNegotiator
  alias Libp2p.Transport.Tcp

  @type t :: pid() | atom()

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    if Keyword.has_key?(opts, :name) do
      case Keyword.get(opts, :name) do
        nil -> GenServer.start_link(__MODULE__, opts)
        name -> GenServer.start_link(__MODULE__, opts, name: name)
      end
    else
      GenServer.start_link(__MODULE__, opts, name: __MODULE__)
    end
  end

  @doc """
  Start listening on `{ip, port}`.
  """
  @spec listen(t(), :inet.ip_address(), :inet.port_number()) :: {:ok, Tcp.socket()} | {:error, term()}
  def listen(swarm, ip, port) do
    GenServer.call(swarm, {:listen, ip, port})
  end

  @doc """
  Dial a peer at `{ip, port}`.
  """
  @spec dial(t(), :inet.ip_address(), :inet.port_number()) :: {:ok, pid()} | {:error, term()}
  def dial(swarm, ip, port) do
    dial(swarm, ip, port, [])
  end

  @spec dial(t(), :inet.ip_address(), :inet.port_number(), keyword()) :: {:ok, pid()} | {:error, term()}
  def dial(swarm, ip, port, opts) do
    timeout = Keyword.get(opts, :timeout, 20_000)
    GenServer.call(swarm, {:dial, ip, port, timeout}, timeout + 1_000)
  end

  @impl true
  def init(opts) do
    identity = Keyword.fetch!(opts, :identity)
    peer_store = Keyword.fetch!(opts, :peer_store)
    conn_sup = Keyword.fetch!(opts, :connection_supervisor)

    st = %{
      identity: identity,
      peer_store: peer_store,
      connection_supervisor: conn_sup,
      listeners: %{},
      connections: MapSet.new(),
      streams: %{},
      protocol_handlers: Keyword.get(opts, :protocol_handlers, %{}),
      gossipsub: Keyword.get(opts, :gossipsub, nil)
    }

    {:ok, st}
  end

  @impl true
  def handle_call({:listen, ip, port}, _from, st) do
    case Tcp.listen(ip, port) do
      {:ok, listener} ->
        swarm_pid = self()
        accept_pid =
          spawn_link(fn ->
            accept_loop(%{
              swarm: swarm_pid,
              listener: listener,
              connection_supervisor: st.connection_supervisor,
              identity: st.identity,
              peer_store: st.peer_store
            })
          end)

        # Best-effort: move the listening socket to the accept loop process.
        _ = :gen_tcp.controlling_process(listener, accept_pid)
        {:reply, {:ok, listener}, %{st | listeners: Map.put(st.listeners, listener, {ip, port})}}

      {:error, reason} ->
        {:reply, {:error, reason}, st}
    end
  end

  def handle_call({:dial, ip, port, ready_timeout}, _from, st) do
    # V2 handles socket creation internally for initiators.
    case start_connection(st, :outbound, {ip, port}) do
      {:ok, pid} ->
        case Libp2p.ConnectionV2.await_ready(pid, ready_timeout) do
          :ok -> {:reply, {:ok, pid}, st}
          {:error, reason} -> {:reply, {:error, reason}, st}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, st}
    end
  end

  @impl true
  def handle_info({:inbound_stream, conn, stream_id}, st) do
    supported = MapSet.new(Map.keys(st.protocol_handlers))

    # We monitor the task to clean up streams map when it exits
    {%Task{pid: pid}, _} =
      Task.Supervisor.start_child(Libp2p.TaskSupervisor, fn ->
        # Optimize: try to take ownership directly to bypass Swarm for future data
        # (This handles the race where data comes *after* this call, while Swarm/handle_info handles data *before*)
        try do
           Libp2p.ConnectionV2.set_stream_handler(conn, stream_id, self())
        rescue
           # Connection might be V1 or closed
           _ -> :ok
        end

        case StreamNegotiator.negotiate_inbound(conn, stream_id, supported) do
          {:ok, proto, initial} ->
            case Map.get(st.protocol_handlers, proto) do
              nil ->
                _ = Libp2p.Connection.stream_close(conn, stream_id)
                :ok

              handler when is_function(handler, 3) ->
                handler.(conn, stream_id, initial)

              handler when is_function(handler, 4) ->
                handler.(conn, stream_id, proto, initial)

              handler_mod when is_atom(handler_mod) ->
                res =
                  cond do
                    function_exported?(handler_mod, :handle_inbound, 4) ->
                      handler_mod.handle_inbound(conn, stream_id, proto, initial)

                    function_exported?(handler_mod, :handle_inbound, 3) ->
                      handler_mod.handle_inbound(conn, stream_id, initial)

                    true ->
                      _ = Libp2p.Connection.stream_close(conn, stream_id)
                      :error
                  end

                case res do
                  {:ok, pid} when is_pid(pid) ->
                    # Transfer ownership to the new handler process
                    Libp2p.ConnectionV2.set_stream_handler(conn, stream_id, pid)

                  _ -> :ok
                end
            end

          {:error, _} ->
            _ = Libp2p.Connection.stream_close(conn, stream_id)
            :ok
        end
      end)

    Process.monitor(pid)
    {:noreply, %{st | streams: Map.put(st.streams, stream_id, pid)}}
  end

  def handle_info({:libp2p, :stream_data, _conn, stream_id, _data, _peer} = msg, st) do
    case Map.get(st.streams, stream_id) do
      pid when is_pid(pid) -> send(pid, msg)
      _ -> :ok # Drop if no handler known (or already finished)
    end
    {:noreply, st}
  end

  def handle_info({:libp2p, :stream_closed, _conn, stream_id, _peer} = msg, st) do
    case Map.get(st.streams, stream_id) do
      pid when is_pid(pid) -> send(pid, msg)
      _ -> :ok
    end
    # We don't remove from map yet, we wait for task DOWN?
    # Or we can remove now if we know task will exit?
    # Protocol handler might do cleanup.
    {:noreply, st}
  end

  def handle_info({:connection_ready, conn, peer_id}, st) do
    if is_pid(st.gossipsub) or is_atom(st.gossipsub) do
      _ = Libp2p.Gossipsub.peer_connected(st.gossipsub, peer_id, conn)
    end

    {:noreply, st}
  end

  def handle_info({:DOWN, _ref, :process, pid, _reason}, st) do
    # Remove any streams handled by this PID
    # Linear scan is inefficient but safer than complex link map for now
    streams =
      Enum.reject(st.streams, fn {_sid, p} -> p == pid end)
      |> Map.new()

    {:noreply, %{st | streams: streams}}
  end

  def handle_info(_msg, st), do: {:noreply, st}

  defp accept_loop(%{swarm: _swarm_pid, listener: listener} = ctx) do
    case Tcp.accept(listener, 30_000) do
      {:ok, sock} ->
        # Start inbound connection from this accept-loop (current owner), then hand socket off.
        case start_inbound_connection(ctx, sock) do
          {:ok, _pid} -> :ok
          {:error, _} -> _ = Tcp.close(sock)
        end

        accept_loop(ctx)

      {:error, _} ->
        :ok
    end
  end

  defp start_inbound_connection(ctx, sock) do
    child_spec =
      {Libp2p.ConnectionV2,
       [
         role: :responder,
         socket: sock,
         identity: ctx.identity,
         peer_store: ctx.peer_store,
         handler: ctx.swarm, # notify Swarm on stream events
         notify_conn_ready?: true, # notify Swarm when connection ready
         noise_prologue: "",
         noise_hash_protocol_name?: false # default compatibility
       ]}

    case DynamicSupervisor.start_child(ctx.connection_supervisor, child_spec) do
      {:ok, pid} ->
        case :gen_tcp.controlling_process(sock, pid) do
          :ok ->
            send(pid, :start_socket) # V2 expects :start_socket or implicit start?
            # V2 listener logic usually sets active:once in init or handle_continue.
            # V2 Listener.ex sends :start_socket. ConnectionV2 handles it.
            {:ok, pid}

          {:error, reason} ->
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp start_connection(st, :outbound, {ip, port}) do
    child_spec =
      {Libp2p.ConnectionV2,
       [
         role: :initiator,
         dial: {ip, port},
         identity: st.identity,
         peer_store: st.peer_store,
         handler: self(), # Swarm
         notify_conn_ready?: true,
         noise_prologue: "",
         dial_timeout_ms: 5_000
       ]}

    DynamicSupervisor.start_child(st.connection_supervisor, child_spec)
  end
end
