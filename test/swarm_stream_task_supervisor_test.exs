defmodule Libp2p.SwarmStreamTaskSupervisorTest do
  use ExUnit.Case, async: false

  alias Libp2p.{Identity, PeerStore, StreamNegotiator, Swarm}
  alias Libp2p.Transport.Tcp

  @proto "/echo/local-task-supervisor/1.0.0"

  defmodule EchoHandler do
    @moduledoc false

    def handle_inbound(conn, stream_id, initial_data) do
      Libp2p.ConnectionV2.set_stream_handler(conn, stream_id, self())

      if initial_data != <<>> do
        Libp2p.ConnectionV2.send_stream(conn, stream_id, initial_data)
      end

      loop(conn, stream_id)
    end

    defp loop(conn, stream_id) do
      receive do
        {:libp2p, :stream_data, ^conn, ^stream_id, data} ->
          Libp2p.ConnectionV2.send_stream(conn, stream_id, data)
          loop(conn, stream_id)

        {:libp2p, :stream_closed, ^conn, ^stream_id} ->
          :ok
      end
    end
  end

  test "swarm routes inbound streams through configured task supervisor" do
    refute Process.whereis(Libp2p.RpcStreamSupervisor)

    id_a = Identity.generate_secp256k1()
    id_b = Identity.generate_secp256k1()

    {:ok, ps_a} = PeerStore.start_link(name: nil)
    {:ok, cs_a} = DynamicSupervisor.start_link(strategy: :one_for_one)
    {:ok, rpc_sup_a} = Task.Supervisor.start_link()

    {:ok, swarm_a} =
      Swarm.start_link(
        name: nil,
        identity: id_a,
        peer_store: ps_a,
        connection_supervisor: cs_a,
        stream_task_supervisor: rpc_sup_a,
        protocol_handlers: %{@proto => EchoHandler}
      )

    {:ok, ps_b} = PeerStore.start_link(name: nil)
    {:ok, cs_b} = DynamicSupervisor.start_link(strategy: :one_for_one)
    {:ok, rpc_sup_b} = Task.Supervisor.start_link()

    {:ok, swarm_b} =
      Swarm.start_link(
        name: nil,
        identity: id_b,
        peer_store: ps_b,
        connection_supervisor: cs_b,
        stream_task_supervisor: rpc_sup_b
      )

    {:ok, listener} = Swarm.listen(swarm_a, {127, 0, 0, 1}, 0)
    {:ok, {{127, 0, 0, 1}, port}} = Tcp.sockname(listener)

    {:ok, conn_pid} = Swarm.dial(swarm_b, {127, 0, 0, 1}, port, timeout: 20_000)
    assert :ok = Libp2p.Connection.await_ready(conn_pid, 10_000)

    {:ok, stream_id} = Libp2p.ConnectionV2.open_stream(conn_pid)
    :ok = Libp2p.ConnectionV2.set_stream_handler(conn_pid, stream_id, self())

    assert {:ok, @proto, <<>>} =
             StreamNegotiator.negotiate_outbound(
               conn_pid,
               stream_id,
               [@proto],
               MapSet.new([@proto])
             )

    :ok = Libp2p.ConnectionV2.send_stream(conn_pid, stream_id, "hello")

    assert_receive {:libp2p, :stream_data, ^conn_pid, ^stream_id, "hello"}, 5_000
  end
end
