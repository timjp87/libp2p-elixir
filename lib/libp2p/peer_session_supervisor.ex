defmodule Libp2p.PeerSessionSupervisor do
  @moduledoc """
  Dynamic supervisor for managing PeerSession processes.
  """

  use DynamicSupervisor

  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts) do
    DynamicSupervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @spec start_peer_session(binary()) :: DynamicSupervisor.on_start_child()
  def start_peer_session(peer_id) do
    DynamicSupervisor.start_child(__MODULE__, {Libp2p.PeerSession, peer_id: peer_id})
  end

  @impl true
  def init(_opts) do
    DynamicSupervisor.init(strategy: :one_for_one)
  end
end
