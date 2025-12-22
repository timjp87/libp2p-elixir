defmodule Libp2p.Supervisor do
  @moduledoc """
  Top-level supervisor for the Libp2p application.

  This supervisor starts the core components of the stack:
  - `Libp2p.Swarm`: Manages connections and listeners.
  - `Libp2p.PeerStore`: Manages peer metadata (keys, addresses).
  """

  use Supervisor

  alias Libp2p.{Gossipsub, PeerStore, Protocol, Swarm, PeerSessionSupervisor}

  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts) do
    Supervisor.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl true
  def init(opts) do
    peer_store_name = Keyword.get(opts, :peer_store_name, PeerStore)
    conn_sup_name = Keyword.get(opts, :connection_supervisor_name, Libp2p.ConnectionSupervisor)
    swarm_name = Keyword.get(opts, :swarm_name, Swarm)
    gossipsub_name = Keyword.get(opts, :gossipsub_name, Gossipsub)

    children = [
      {Registry, keys: :unique, name: Libp2p.PeerRegistry},
      {PeerStore, name: peer_store_name},
      {PeerSessionSupervisor, name: Libp2p.PeerSessionSupervisor},
      {DynamicSupervisor, name: conn_sup_name, strategy: :one_for_one},
      {Task.Supervisor, name: Libp2p.RpcStreamSupervisor},
      {Gossipsub, name: gossipsub_name},
      {Swarm,
       [
         name: swarm_name,
         peer_store: peer_store_name,
         connection_supervisor: conn_sup_name,
         peer_session_supervisor: Libp2p.PeerSessionSupervisor,
         identity: Keyword.fetch!(opts, :identity),
         gossipsub: gossipsub_name,
         protocol_handlers:
           Keyword.get(opts, :protocol_handlers, %{
             Protocol.identify() => Libp2p.Identify,
             Protocol.identify_push() => Libp2p.Identify,
             Protocol.gossipsub_1_1() => Libp2p.Gossipsub
           })
       ]}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
