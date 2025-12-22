defmodule Libp2p.GossipsubIntegrationTest do
  use ExUnit.Case, async: false

  alias Libp2p.{Gossipsub, Identity, PeerStore, Protocol, Swarm}
  alias Libp2p.Transport.Tcp

  setup do
    _ = Registry.start_link(keys: :unique, name: Libp2p.PeerRegistry)
    _ = Task.Supervisor.start_link(name: Libp2p.RpcStreamSupervisor)
    :ok
  end

  test "gossipsub can subscribe and propagate a message between two swarms" do
    topic = "/test/1"
    payload = "hello"

    parent = self()

    {:ok, gsp_a} =
      Gossipsub.start_link(
        name: nil,
        event_sink: parent,
        on_message: fn t, data, _from ->
          send(parent, {:a_msg, t, data})
        end
      )

    {:ok, gsp_b} =
      Gossipsub.start_link(
        name: nil,
        event_sink: parent,
        on_message: fn t, data, _from ->
          send(parent, {:b_msg, t, data})
        end
      )

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
        gossipsub: gsp_a,
        protocol_handlers: %{
          Protocol.gossipsub_1_1() => fn conn, sid, initial ->
            Gossipsub.handle_inbound(gsp_a, conn, sid, initial)
          end
        }
      )

    {:ok, ps_b} = PeerStore.start_link(name: nil)
    {:ok, cs_b} = DynamicSupervisor.start_link(strategy: :one_for_one)

    {:ok, swarm_b} =
      Swarm.start_link(
        name: nil,
        identity: id_b,
        peer_store: ps_b,
        connection_supervisor: cs_b,
        gossipsub: gsp_b,
        protocol_handlers: %{
          Protocol.gossipsub_1_1() => fn conn, sid, initial ->
            Gossipsub.handle_inbound(gsp_b, conn, sid, initial)
          end
        }
      )

    {:ok, listener} = Swarm.listen(swarm_a, {127, 0, 0, 1}, 0)
    {:ok, {{127, 0, 0, 1}, port}} = Tcp.sockname(listener)

    {:ok, conn_pid} = Swarm.dial(swarm_b, {127, 0, 0, 1}, port, timeout: 20_000)
    assert :ok = Libp2p.Connection.await_ready(conn_pid, 10_000)
    {:ok, peer_a} = Libp2p.Connection.remote_peer_id(conn_pid)
    :ok = Gossipsub.peer_connected(gsp_b, peer_a, conn_pid)

    case Gossipsub.await_peer(gsp_b, peer_a, 10_000) do
      :ok -> :ok
      other -> flunk("await_peer failed: #{inspect(other)}")
    end

    # Subscribe on both sides.
    :ok = Gossipsub.subscribe(gsp_a, topic)
    :ok = Gossipsub.subscribe(gsp_b, topic)

    # Publish from B; expect A receives.
    :ok = Gossipsub.publish(gsp_b, topic, payload)
    assert_receive {:a_msg, ^topic, ^payload}, 5_000
  end
end
