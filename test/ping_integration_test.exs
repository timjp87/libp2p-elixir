defmodule Libp2p.PingIntegrationTest do
  use ExUnit.Case, async: false

  alias Libp2p.{Identity, PeerStore, Ping, Swarm}
  alias Libp2p.Transport.Tcp

  setup do
    _ = Registry.start_link(keys: :unique, name: Libp2p.PeerRegistry)
    _ = Task.Supervisor.start_link(name: Libp2p.RpcStreamSupervisor)
    :ok
  end

  test "ping round trip works through default swarm handlers" do
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
        protocol_handlers: %{}
      )

    {:ok, ps_b} = PeerStore.start_link(name: nil)
    {:ok, cs_b} = DynamicSupervisor.start_link(strategy: :one_for_one)

    {:ok, swarm_b} =
      Swarm.start_link(
        name: nil,
        identity: id_b,
        peer_store: ps_b,
        connection_supervisor: cs_b,
        protocol_handlers: %{}
      )

    {:ok, listener} = Swarm.listen(swarm_a, {127, 0, 0, 1}, 0)
    {:ok, {{127, 0, 0, 1}, port}} = Tcp.sockname(listener)

    {:ok, conn_pid} = Swarm.dial(swarm_b, {127, 0, 0, 1}, port, timeout: 20_000)
    assert :ok = Libp2p.Connection.await_ready(conn_pid, 10_000)

    assert {:ok, rtt_us} =
             Ping.ping(conn_pid,
               payload: :binary.copy(<<0xA5>>, 32),
               timeout: 10_000
             )

    assert is_integer(rtt_us)
    assert rtt_us >= 0
  end

  test "ping rejects invalid payload sizes" do
    assert {:error, :invalid_payload} = Ping.ping(self(), payload: <<1, 2, 3>>)
  end
end
