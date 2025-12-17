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
    with {:ok, sock} <- Tcp.dial(ip, port) do
      case start_connection(st, :outbound, sock) do
        {:ok, pid} ->
          case Libp2p.Connection.await_ready(pid, ready_timeout) do
            :ok -> {:reply, {:ok, pid}, st}
            {:error, reason} -> {:reply, {:error, reason}, st}
          end

        {:error, reason} ->
          {:reply, {:error, reason}, st}
      end
    else
      {:error, reason} -> {:reply, {:error, reason}, st}
    end
  end

  @impl true
  def handle_info({:inbound_stream, conn, stream_id}, st) do
    supported = MapSet.new(Map.keys(st.protocol_handlers))

    Task.start(fn ->
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
              cond do
                function_exported?(handler_mod, :handle_inbound, 4) ->
                  handler_mod.handle_inbound(conn, stream_id, proto, initial)

                function_exported?(handler_mod, :handle_inbound, 3) ->
                handler_mod.handle_inbound(conn, stream_id, initial)

                true ->
                  _ = Libp2p.Connection.stream_close(conn, stream_id)
              end
          end

        {:error, _} ->
          _ = Libp2p.Connection.stream_close(conn, stream_id)
          :ok
      end
    end)

    {:noreply, st}
  end

  def handle_info({:connection_ready, conn, peer_id}, st) do
    if is_pid(st.gossipsub) or is_atom(st.gossipsub) do
      _ = Libp2p.Gossipsub.peer_connected(st.gossipsub, peer_id, conn)
    end

    {:noreply, st}
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
      {Libp2p.Connection,
       [swarm: ctx.swarm, socket: sock, direction: :inbound, identity: ctx.identity, peer_store: ctx.peer_store]}

    case DynamicSupervisor.start_child(ctx.connection_supervisor, child_spec) do
      {:ok, pid} ->
        case :gen_tcp.controlling_process(sock, pid) do
          :ok ->
            send(pid, :start_upgrade)
            {:ok, pid}

          {:error, reason} ->
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp start_connection(st, direction, sock) when direction in [:inbound, :outbound] do
    child_spec =
      {Libp2p.Connection,
       [swarm: self(), socket: sock, direction: direction, identity: st.identity, peer_store: st.peer_store]}

    case DynamicSupervisor.start_child(st.connection_supervisor, child_spec) do
      {:ok, pid} ->
        case :gen_tcp.controlling_process(sock, pid) do
          :ok ->
            send(pid, :start_upgrade)
            {:ok, pid}
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end
end
