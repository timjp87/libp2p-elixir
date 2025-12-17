defmodule Libp2p.RequestResponseIntegrationTest do
  use ExUnit.Case, async: false

  alias Libp2p.{Identity, PeerStore, ReqRespServer, RequestResponse, Swarm}
  alias Libp2p.Transport.Tcp

  test "request-response round trip" do
    proto = "/test/reqresp/1"

    id_a = Identity.generate_secp256k1()
    id_b = Identity.generate_secp256k1()

    {:ok, gate} = ReqRespServer.start_link(name: nil)

    {:ok, ps_a} = PeerStore.start_link(name: nil)
    {:ok, cs_a} = DynamicSupervisor.start_link(strategy: :one_for_one)
    {:ok, rr_a} = RequestResponse.start_link(name: nil, concurrency_server: gate)
    :ok = RequestResponse.register(rr_a, proto, fn _peer_id, req -> "pong:" <> req end)

    {:ok, swarm_a} =
      Swarm.start_link(
        name: nil,
        identity: id_a,
        peer_store: ps_a,
        connection_supervisor: cs_a,
        protocol_handlers: %{
          proto => fn conn, sid, selected_proto, initial -> RequestResponse.handle_inbound(rr_a, conn, sid, selected_proto, initial) end
        }
      )

    {:ok, ps_b} = PeerStore.start_link(name: nil)
    {:ok, cs_b} = DynamicSupervisor.start_link(strategy: :one_for_one)
    {:ok, rr_b} = RequestResponse.start_link(name: nil, concurrency_server: gate)

    {:ok, swarm_b} =
      Swarm.start_link(
        name: nil,
        identity: id_b,
        peer_store: ps_b,
        connection_supervisor: cs_b,
        protocol_handlers: %{
          proto => fn conn, sid, selected_proto, initial -> RequestResponse.handle_inbound(rr_b, conn, sid, selected_proto, initial) end
        }
      )

    {:ok, listener} = Swarm.listen(swarm_a, {127, 0, 0, 1}, 0)
    {:ok, {{127, 0, 0, 1}, port}} = Tcp.sockname(listener)

    {:ok, conn_pid} = Swarm.dial(swarm_b, {127, 0, 0, 1}, port, timeout: 20_000)
    assert :ok = Libp2p.Connection.await_ready(conn_pid, 10_000)

    assert {:ok, "pong:ping"} = RequestResponse.request(rr_b, conn_pid, proto, "ping", timeout: 10_000)
  end
end
