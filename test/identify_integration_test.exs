defmodule Libp2p.IdentifyIntegrationTest do
  use ExUnit.Case, async: false

  alias Libp2p.{Identity, PeerStore, Protocol, Swarm}
  alias Libp2p.Transport.Tcp

  defmodule FakeConn do
    def open_stream(parent) do
      send(parent, :open_stream)
      {:ok, 11}
    end

    def open_stream(parent, data) do
      send(parent, {:open_stream, data})
      {:ok, 11}
    end
  end

  setup do
    _ = Registry.start_link(keys: :unique, name: Libp2p.PeerRegistry)
    _ = Task.Supervisor.start_link(name: Libp2p.RpcStreamSupervisor)
    :ok
  end

  test "opens identify negotiation stream with initial multistream bytes" do
    assert {:ok, 11} =
             Libp2p.Identify.open_negotiation_stream(self(), "/ipfs/id/1.0.0\n", FakeConn)

    assert_received {:open_stream, "/ipfs/id/1.0.0\n"}
    refute_received :open_stream
  end

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

    assert {:ok, %Libp2p.PeerInfo{} = info} = Libp2p.Identify.request(conn_pid, ps_b)
    assert info.peer_id == remote_peer_id
    assert %Libp2p.PeerInfo{} = PeerStore.get(ps_b, remote_peer_id)
  end
end
