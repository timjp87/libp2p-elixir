defmodule Libp2p.PeerStore do
  @moduledoc """
  Minimal peer store for tracking addresses + supported protocols.

  This is a minimal implementation focusing on essential libp2p features.
  """

  use GenServer

  alias Libp2p.{Multiaddr, PeerInfo}

  @type peer_id :: binary()

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    if Keyword.has_key?(opts, :name) do
      case Keyword.get(opts, :name) do
        nil -> GenServer.start_link(__MODULE__, %{})
        name -> GenServer.start_link(__MODULE__, %{}, name: name)
      end
    else
      GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
    end
  end

  @spec get(pid() | atom(), peer_id()) :: PeerInfo.t() | nil
  def get(server, peer_id) when is_binary(peer_id) do
    GenServer.call(server, {:get, peer_id})
  end

  @spec upsert(pid() | atom(), PeerInfo.t()) :: :ok
  def upsert(server, %PeerInfo{peer_id: peer_id} = info) when is_binary(peer_id) do
    GenServer.call(server, {:upsert, info})
  end

  @spec add_addr(pid() | atom(), peer_id(), Multiaddr.t()) :: :ok
  def add_addr(server, peer_id, %Multiaddr{} = addr) when is_binary(peer_id) do
    GenServer.call(server, {:add_addr, peer_id, addr})
  end

  @spec add_protocols(pid() | atom(), peer_id(), [binary()]) :: :ok
  def add_protocols(server, peer_id, protos) when is_binary(peer_id) and is_list(protos) do
    GenServer.call(server, {:add_protocols, peer_id, protos})
  end

  @spec mark_seen(pid() | atom(), peer_id()) :: :ok
  def mark_seen(server, peer_id) when is_binary(peer_id) do
    GenServer.call(server, {:mark_seen, peer_id})
  end

  @impl true
  def init(state), do: {:ok, state}

  @impl true
  def handle_call({:get, peer_id}, _from, st) do
    {:reply, Map.get(st, peer_id), st}
  end

  def handle_call({:upsert, %PeerInfo{} = info}, _from, st) do
    {:reply, :ok, Map.put(st, info.peer_id, info)}
  end

  def handle_call({:add_addr, peer_id, %Multiaddr{} = addr}, _from, st) do
    info = Map.get(st, peer_id) || %PeerInfo{peer_id: peer_id}
    info = %{info | addrs: uniq_addrs([addr | info.addrs])}
    {:reply, :ok, Map.put(st, peer_id, info)}
  end

  def handle_call({:add_protocols, peer_id, protos}, _from, st) do
    info = Map.get(st, peer_id) || %PeerInfo{peer_id: peer_id}
    info = %{info | protocols: Enum.reduce(protos, info.protocols, &MapSet.put(&2, &1))}
    {:reply, :ok, Map.put(st, peer_id, info)}
  end

  def handle_call({:mark_seen, peer_id}, _from, st) do
    info = Map.get(st, peer_id) || %PeerInfo{peer_id: peer_id}
    info = %{info | last_seen_ms: System.system_time(:millisecond)}
    {:reply, :ok, Map.put(st, peer_id, info)}
  end

  defp uniq_addrs(addrs) do
    addrs
    |> Enum.uniq_by(& &1.bytes)
  end
end
