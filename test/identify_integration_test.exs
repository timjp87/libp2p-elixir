defmodule Libp2p.IdentifyIntegrationTest do
  use ExUnit.Case, async: false

  alias Libp2p.{Identity, PeerStore, Protocol, Swarm}
  alias Libp2p.Transport.Tcp

  test "identify request populates peerstore" do
    id_a = Identity.generate_secp256k1()
    id_b = Identity.generate_secp256k1()

    {:ok, ps_a} = PeerStore.start_link(name: nil)
    {:ok, cs_a} = DynamicSupervisor.start_link(strategy: :one_for_one)

    {:ok, swarm_a} =
      Swarm.start_link(
        name: nil,
        identity: id_a,
        peer_store: ps_a,
        connection_supervisor: cs_a,
        protocol_handlers: %{Protocol.identify() => Libp2p.Identify}
      )

    {:ok, ps_b} = PeerStore.start_link(name: nil)
    {:ok, cs_b} = DynamicSupervisor.start_link(strategy: :one_for_one)

    {:ok, swarm_b} =
      Swarm.start_link(
        name: nil,
        identity: id_b,
        peer_store: ps_b,
        connection_supervisor: cs_b,
        protocol_handlers: %{Protocol.identify() => Libp2p.Identify}
      )

    {:ok, listener} = Swarm.listen(swarm_a, {127, 0, 0, 1}, 0)
    {:ok, {{127, 0, 0, 1}, port}} = Tcp.sockname(listener)

    {:ok, conn_pid} = Swarm.dial(swarm_b, {127, 0, 0, 1}, port, timeout: 20_000)
    assert :ok = Libp2p.Connection.await_ready(conn_pid, 10_000)

    {:ok, remote_peer_id} = Libp2p.Connection.remote_peer_id(conn_pid)

    assert :ok = Libp2p.Identify.request(conn_pid, ps_b)
    assert %Libp2p.PeerInfo{} = PeerStore.get(ps_b, remote_peer_id)
  end
end
