defmodule Libp2p.ConnUpgradeTest do
  use ExUnit.Case, async: true

  alias Libp2p.{ConnUpgrade, Identity}
  alias Libp2p.Transport.Tcp

  test "upgrades a local TCP connection via MSS->Noise->Yamux" do
    id_a = Identity.generate_secp256k1()
    id_b = Identity.generate_secp256k1()

    {:ok, listener} = Tcp.listen({127, 0, 0, 1}, 0)
    {:ok, {{127, 0, 0, 1}, port}} = Tcp.sockname(listener)

    # Accept in background to avoid deadlock.
    parent = self()

    accept_task =
      spawn_link(fn ->
        {:ok, sock_in} = Tcp.accept(listener, 5_000)
        :ok = :gen_tcp.controlling_process(sock_in, parent)
        send(parent, {:accepted, sock_in})
      end)

    _ = accept_task

    {:ok, sock_out} = Tcp.dial({127, 0, 0, 1}, port, timeout: 5_000)
    assert_receive {:accepted, sock_in}, 5_000

    # Upgrade both sides concurrently.
    t1 =
      Task.async(fn ->
        ConnUpgrade.upgrade_inbound(sock_in, id_b, timeout: 5_000)
      end)

    t2 =
      Task.async(fn ->
        ConnUpgrade.upgrade_outbound(sock_out, id_a, timeout: 5_000)
      end)

    assert {:ok, _secure_in, _yamux_in, _remote_peer_in} = Task.await(t1, 10_000)
    assert {:ok, _secure_out, _yamux_out, _remote_peer_out} = Task.await(t2, 10_000)
  end
end
