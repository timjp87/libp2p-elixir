defmodule Libp2p.ReqRespServerTest do
  use ExUnit.Case, async: true

  alias Libp2p.ReqRespServer

  test "enforces max concurrent requests per key" do
    {:ok, srv} = start_supervised(ReqRespServer)

    key = {"peerA", "/eth2/beacon_chain/req/status/1/"}

    parent = self()

    slow = fn _req ->
      send(parent, {:started, self()})
      receive do
        :finish -> :ok
      after
        5_000 -> raise "timeout"
      end

      "resp"
    end

    t1 = Task.async(fn -> ReqRespServer.handle(srv, key, "req1", slow, max_concurrent: 1, timeout: 2_000) end)
    assert_receive {:started, handler_pid}

    # second should be rejected immediately
    assert {:error, :max_concurrent_requests} ==
             ReqRespServer.handle(srv, key, "req2", fn _ -> "resp2" end, max_concurrent: 1, timeout: 2_000)

    send(handler_pid, :finish)
    assert {:ok, "resp"} == Task.await(t1, 5_000)
  end
end
