defmodule Libp2p.SwarmRuntimeTest do
  use ExUnit.Case, async: false

  alias Libp2p.{Identity, PeerStore, Swarm}
  alias Libp2p.Transport.Tcp

  setup do
    _ = Registry.start_link(keys: :unique, name: Libp2p.PeerRegistry)
    _ = Task.Supervisor.start_link(name: Libp2p.RpcStreamSupervisor)
    :ok
  end

  test "swarm can listen and accept a dial" do
    id_a = Identity.generate_secp256k1()
    id_b = Identity.generate_secp256k1()

    {:ok, ps_a} = PeerStore.start_link(name: nil)
    {:ok, cs_a} = DynamicSupervisor.start_link(strategy: :one_for_one)

    {:ok, swarm_a} =
      Swarm.start_link(name: nil, identity: id_a, peer_store: ps_a, connection_supervisor: cs_a)

    {:ok, ps_b} = PeerStore.start_link(name: nil)
    {:ok, cs_b} = DynamicSupervisor.start_link(strategy: :one_for_one)

    {:ok, swarm_b} =
      Swarm.start_link(name: nil, identity: id_b, peer_store: ps_b, connection_supervisor: cs_b)

    {:ok, listener} = Swarm.listen(swarm_a, {127, 0, 0, 1}, 0)
    {:ok, {{127, 0, 0, 1}, port}} = Tcp.sockname(listener)

    assert {:ok, conn_pid} = Swarm.dial(swarm_b, {127, 0, 0, 1}, port)
    assert Process.alive?(conn_pid)

    assert :ok = Libp2p.Connection.await_ready(conn_pid, 5_000)
    assert {:ok, _stream_id} = Libp2p.Connection.open_stream(conn_pid)
  end
end
