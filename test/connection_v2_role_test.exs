defmodule Libp2p.ConnectionV2RoleTest do
  use ExUnit.Case, async: false

  alias Libp2p.{ConnectionV2, Identity, PeerStore}

  @tcp_opts [:binary, packet: :raw, active: false, reuseaddr: true, ip: {127, 0, 0, 1}]

  test "role returns the configured connection role" do
    old_trap_exit = Process.flag(:trap_exit, true)
    on_exit(fn -> Process.flag(:trap_exit, old_trap_exit) end)

    {:ok, listener} = :gen_tcp.listen(0, @tcp_opts)
    {:ok, {{127, 0, 0, 1}, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)

    parent = self()

    accept_pid =
      spawn_link(fn ->
        {:ok, sock} = :gen_tcp.accept(listener)
        send(parent, {:accepted, sock})

        receive do
          :close -> :ok
        after
          5_000 -> :ok
        end

        :gen_tcp.close(sock)
      end)

    {:ok, peer_store} = PeerStore.start_link(name: nil)

    {:ok, conn} =
      ConnectionV2.start_link(
        role: :initiator,
        dial: {{127, 0, 0, 1}, port},
        identity: Identity.generate_secp256k1(),
        peer_store: peer_store,
        upgrade_timeout_ms: 5_000,
        dial_timeout_ms: 500
      )

    assert_receive {:accepted, _sock}, 500
    assert ConnectionV2.role(conn) == {:ok, :initiator}

    send(accept_pid, :close)
  end

  test "role returns an error when the process does not answer before the timeout" do
    pid =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    assert match?({:error, _reason}, ConnectionV2.role(pid, 10))

    send(pid, :stop)
  end
end
