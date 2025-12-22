defmodule Libp2p.PeerSession do
  @moduledoc """
  Manages per-peer state and coordination for a connected peer.

  Responsibilities:
  - Track peer metadata (protocol version, agent version, etc.).
  - Manage scoring, bans, and rate limits.
  - Coordinate outbound streams and ensure only one connection exists per peer.
  - Track outstanding requests.
  """

  use GenServer
  require Logger

  @type peer_id :: binary()
  @type state :: %{
          peer_id: peer_id(),
          metadata: map(),
          score: integer(),
          connections: MapSet.t(pid()),
          outstanding_requests: map()
        }

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    peer_id = Keyword.fetch!(opts, :peer_id)
    GenServer.start_link(__MODULE__, opts, name: via_tuple(peer_id))
  end

  defp via_tuple(peer_id) do
    {:via, Registry, {Libp2p.PeerRegistry, peer_id}}
  end

  @spec get_state(peer_id()) :: {:ok, state()} | {:error, :not_found}
  def get_state(peer_id) do
    case Registry.lookup(Libp2p.PeerRegistry, peer_id) do
      [{pid, _}] -> {:ok, GenServer.call(pid, :get_state)}
      [] -> {:error, :not_found}
    end
  end

  @spec register_connection(peer_id(), pid()) :: :ok
  def register_connection(peer_id, conn_pid) do
    GenServer.cast(via_tuple(peer_id), {:register_connection, conn_pid})
  end

  @impl true
  def init(opts) do
    peer_id = Keyword.fetch!(opts, :peer_id)
    # We might want to monitor connections to clean up if they die
    {:ok,
     %{
       peer_id: peer_id,
       metadata: %{},
       score: 0,
       connections: MapSet.new(),
       outstanding_requests: %{}
     }}
  end

  @impl true
  def handle_call(:get_state, _from, st) do
    {:reply, st, st}
  end

  @impl true
  def handle_cast({:register_connection, conn_pid}, st) do
    Process.monitor(conn_pid)
    {:noreply, %{st | connections: MapSet.put(st.connections, conn_pid)}}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, _reason}, st) do
    if MapSet.member?(st.connections, pid) do
      connections = MapSet.delete(st.connections, pid)

      if MapSet.size(connections) == 0 do
        # Should we stop the session if no connections are left?
        # Typically yes, but we might want to keep it briefly for "idle" state
        # as suggested in the architecture plan.
        {:noreply, %{st | connections: connections}}
      else
        {:noreply, %{st | connections: connections}}
      end
    else
      {:noreply, st}
    end
  end
end
