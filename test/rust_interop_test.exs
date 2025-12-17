defmodule Libp2p.RustInteropTest do
  use ExUnit.Case, async: false

  @moduletag timeout: 240_000

  alias Libp2p.{Gossipsub, Identity, Identify, PeerStore, Protocol, RequestResponse, ReqRespServer, Swarm}

  @harness_dir "/Users/timjester-pfadt/dev/ethereum/panacea/third_party/rust_libp2p_harness"
  @harness_bin "/Users/timjester-pfadt/dev/ethereum/panacea/third_party/rust_libp2p_harness/target/debug/rust_libp2p_harness"

  test "interop: connect (tcp+noise+yamux) + identify + gossipsub + request-response" do
    {port, listen_port} = start_rust_harness!()
    on_exit(fn ->
      try do
        Port.close(port)
      catch
        _, _ -> :ok
      end
    end)

    id = Identity.generate_secp256k1()
    {:ok, ps} = PeerStore.start_link(name: nil)
    {:ok, cs} = DynamicSupervisor.start_link(strategy: :one_for_one)

    parent = self()

    {:ok, gsp} =
      Gossipsub.start_link(
        name: nil,
        on_message: fn topic, data, _from -> send(parent, {:gs_msg, topic, data}) end
      )

    # Subscribe before dialing to minimize race with Rust publishing.
    :ok = Gossipsub.subscribe(gsp, "/test/1")

    {:ok, gate} = ReqRespServer.start_link(name: nil)
    {:ok, rr} = RequestResponse.start_link(name: nil, concurrency_server: gate)

    {:ok, swarm} =
      Swarm.start_link(
        name: nil,
        identity: id,
        peer_store: ps,
        connection_supervisor: cs,
        gossipsub: gsp,
        protocol_handlers: %{
          Protocol.identify() => Libp2p.Identify,
          Protocol.identify_push() => Libp2p.Identify,
          Protocol.gossipsub_1_1() => fn conn, sid, initial -> Gossipsub.handle_inbound(gsp, conn, sid, initial) end
        }
      )

    # Connect (tcp+noise+yomux)
    {:ok, conn} = Swarm.dial(swarm, {127, 0, 0, 1}, listen_port, timeout: 30_000)
    assert :ok = Libp2p.Connection.await_ready(conn, 20_000)

    # Identify (Elixir initiates identify request to Rust)
    assert :ok = Identify.request(conn, ps)
    {:ok, remote_peer_id} = Libp2p.Connection.remote_peer_id(conn)
    assert %Libp2p.PeerInfo{} = PeerStore.get(ps, remote_peer_id)

    # Gossipsub: Rust publishes hello_from_rust after a short delay on connection.
    assert_receive {:gs_msg, "/test/1", "hello_from_rust"}, 20_000

    # Request-response: Rust uses 4-byte BE length prefix.
    codec = {&encode_u32/1, &decode_u32/1}
    assert {:ok, "pong:ping"} = RequestResponse.request(rr, conn, "/test/reqresp/1", "ping", timeout: 20_000, codec: codec)
  end

  defp start_rust_harness! do
    port =
      Port.open(
        {:spawn_executable, @harness_bin},
        [
          :binary,
          :exit_status,
          :use_stdio,
          :stderr_to_stdout,
          {:line, 16_384},
          cd: @harness_dir
        ]
      )

    deadline = System.monotonic_time(:millisecond) + 180_000

    case wait_listen(port, deadline, %{listen_port: nil, peer_id: nil, lines: []}) do
      {:ok, p} -> {port, p}
      {:error, lines} -> raise "failed to read LISTEN_ADDR/PEER_ID from rust harness; last output:\n#{Enum.join(lines, "\n")}"
    end
  end

  # (rust log draining omitted; harness output is low-volume)

  defp wait_listen(port, deadline_ms, st) do
    if System.monotonic_time(:millisecond) >= deadline_ms do
      {:error, Enum.take(Enum.reverse(st.lines), 20)}
    else
      receive do
        {^port, {:data, {:eol, line}}} ->
          st =
            st
            |> maybe_set_listen_port(line)
            |> maybe_set_peer_id(line)
            |> Map.update!(:lines, fn lines -> [line | lines] end)

          if st.listen_port != nil and st.peer_id != nil do
            {:ok, st.listen_port}
          else
            wait_listen(port, deadline_ms, st)
          end

        {^port, {:data, {:noeol, line}}} ->
          wait_listen(port, deadline_ms, %{st | lines: [line | st.lines]})

        {^port, {:exit_status, status}} ->
          raise "rust harness exited early with status #{status}"
      after
        250 ->
          wait_listen(port, deadline_ms, st)
      end
    end
  end

  defp maybe_set_peer_id(st, "PEER_ID=" <> rest), do: %{st | peer_id: rest}
  defp maybe_set_peer_id(st, _), do: st

  defp maybe_set_listen_port(st, line) do
    case parse_listen_port(line) do
      {:ok, p} -> %{st | listen_port: p}
      :no -> st
    end
  end

  defp parse_listen_port("LISTEN_ADDR=" <> rest) do
    # Example: /ip4/127.0.0.1/tcp/12345/p2p/12D3KooW...
    case Regex.run(~r{/tcp/(\d+)}, rest) do
      [_, port] -> {:ok, String.to_integer(port)}
      _ -> :no
    end
  end

  defp parse_listen_port(_), do: :no

  defp encode_u32(bin) when is_binary(bin) do
    <<byte_size(bin)::unsigned-big-integer-size(32), bin::binary>>
  end

  defp decode_u32(buf) when is_binary(buf) do
    if byte_size(buf) < 4 do
      :more
    else
      <<len::unsigned-big-integer-size(32), rest::binary>> = buf

      if byte_size(rest) < len do
        :more
      else
        <<msg::binary-size(len), tail::binary>> = rest
        {:ok, msg, tail}
      end
    end
  end
end
