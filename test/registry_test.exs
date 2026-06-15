defmodule Libp2p.RegistryTest do
  use ExUnit.Case, async: true

  alias Libp2p.Registry

  test "pid-qualified unregister does not remove a newer connection for the same peer" do
    name = Module.concat(__MODULE__, :"Registry#{System.unique_integer([:positive])}")
    {:ok, _registry} = start_supervised({Registry, name: name})

    peer_id = "peer-a"
    old_conn = spawn(fn -> Process.sleep(:infinity) end)
    new_conn = spawn(fn -> Process.sleep(:infinity) end)

    on_exit(fn ->
      for pid <- [old_conn, new_conn], Process.alive?(pid), do: Process.exit(pid, :kill)
    end)

    :ok = Registry.register(peer_id, old_conn, name)
    :ok = Registry.register(peer_id, new_conn, name)

    assert Registry.get(peer_id, name) == new_conn

    :ok = Registry.unregister(peer_id, old_conn, name)

    assert Registry.get(peer_id, name) == new_conn
    assert Registry.list(name) == [{peer_id, new_conn}]
  end
end
