defmodule Libp2p.InboundStreamTest do
  use ExUnit.Case, async: false

  alias Libp2p.{ConnectionV2, Identity, InboundStream, MultistreamSelect, PeerStore}

  @tcp_opts [:binary, packet: :raw, active: false, reuseaddr: true, ip: {127, 0, 0, 1}]

  defmodule Handler do
    use GenServer

    def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

    @impl true
    def init(opts) do
      {:ok,
       %{
         identity: Keyword.fetch!(opts, :identity),
         parent: Keyword.fetch!(opts, :parent),
         proto: Keyword.fetch!(opts, :proto),
         response: Keyword.fetch!(opts, :response),
         streams: %{}
       }}
    end

    @impl true
    def handle_info({:libp2p, :conn_ready, _conn, _peer_id}, st), do: {:noreply, st}

    def handle_info({:libp2p, :stream_open, conn, stream_id, peer_id}, st) do
      parent = st.parent
      proto = st.proto
      response = st.response

      {:ok, pid} =
        InboundStream.start_link(
          conn: conn,
          stream_id: stream_id,
          remote_peer_id: peer_id,
          handler_fun: fn selected_proto, data ->
            send(parent, {:handler_called, selected_proto, data})
            response
          end,
          request_complete_fun: fn ^proto, buf ->
            if byte_size(buf) >= 4 do
              <<request::binary-size(4), rest::binary>> = buf
              {:complete, request, rest}
            else
              :more
            end
          end,
          identity: st.identity,
          supported_protocols: MapSet.new([proto])
        )

      Process.monitor(pid)
      {:noreply, %{st | streams: Map.put(st.streams, {conn, stream_id}, pid)}}
    end

    def handle_info({:libp2p, :stream_data, conn, stream_id, data, _peer_id}, st) do
      if pid = Map.get(st.streams, {conn, stream_id}), do: send(pid, {:stream_data, data})
      {:noreply, st}
    end

    def handle_info({:libp2p, :stream_closed, conn, stream_id, _peer_id}, st) do
      if pid = Map.get(st.streams, {conn, stream_id}), do: send(pid, :stream_closed)
      {:noreply, st}
    end

    def handle_info({:DOWN, _ref, :process, pid, _reason}, st) do
      streams =
        st.streams
        |> Enum.reject(fn {_key, stream_pid} -> stream_pid == pid end)
        |> Map.new()

      {:noreply, %{st | streams: streams}}
    end
  end

  test "generic inbound stream responds once request is complete" do
    proto = "/test/inbound-stream/1"
    id_server = Identity.generate_secp256k1()
    id_client = Identity.generate_secp256k1()

    {:ok, handler} =
      Handler.start_link(
        identity: id_server,
        parent: self(),
        proto: proto,
        response: "pong"
      )

    {conn, server_conn} = connected_pair(id_client, id_server, handler)

    on_exit(fn ->
      stop_if_alive(conn)
      stop_if_alive(server_conn)
    end)

    assert {:ok, stream_id, <<>>} = open_negotiated_stream(conn, proto)
    assert :ok = ConnectionV2.send_stream(conn, stream_id, "ping")

    assert_receive {:handler_called, ^proto, "ping"}, 1_000
    assert_receive {:libp2p, :stream_data, ^conn, ^stream_id, "pong"}, 1_000
  end

  defp connected_pair(id_client, id_server, handler) do
    {:ok, ps_client} = PeerStore.start_link(name: nil)
    {:ok, ps_server} = PeerStore.start_link(name: nil)
    {:ok, listener} = :gen_tcp.listen(0, @tcp_opts)
    {:ok, {{127, 0, 0, 1}, port}} = :inet.sockname(listener)

    accept_task =
      Task.async(fn ->
        {:ok, sock} = :gen_tcp.accept(listener, 5_000)

        {:ok, conn} =
          ConnectionV2.start_link(
            role: :responder,
            socket: sock,
            identity: id_server,
            peer_store: ps_server,
            handler: handler,
            notify_conn_ready?: true
          )

        :ok = :gen_tcp.controlling_process(sock, conn)
        send(conn, :start_socket)
        conn
      end)

    {:ok, conn} =
      ConnectionV2.start_link(
        role: :initiator,
        dial: {{127, 0, 0, 1}, port},
        identity: id_client,
        peer_store: ps_client,
        handler: self(),
        notify_conn_ready?: true
      )

    assert :ok = ConnectionV2.await_ready(conn, 5_000)
    server_conn = Task.await(accept_task, 5_000)
    assert :ok = ConnectionV2.await_ready(server_conn, 5_000)
    :gen_tcp.close(listener)

    {conn, server_conn}
  end

  defp open_negotiated_stream(conn, proto) do
    mss = MultistreamSelect.new_initiator([proto])
    {out0, mss} = MultistreamSelect.start(mss)

    with {:ok, stream_id} <- ConnectionV2.open_stream(conn, out0),
         :ok <- ConnectionV2.set_stream_handler(conn, stream_id, self()),
         {:ok, leftover} <- negotiate(conn, stream_id, mss, 5_000) do
      {:ok, stream_id, leftover}
    end
  end

  defp negotiate(conn, stream_id, mss, timeout) do
    receive do
      {:libp2p, :stream_data, ^conn, ^stream_id, data} ->
        {events, out, mss} = MultistreamSelect.feed(mss, data, MapSet.new())
        if out != <<>>, do: :ok = ConnectionV2.send_stream(conn, stream_id, out)

        case Enum.find(events, &match?({:selected, _}, &1)) do
          {:selected, _proto} -> {:ok, Map.get(mss, :buf, <<>>)}
          _ -> negotiate(conn, stream_id, mss, timeout)
        end

      {:libp2p, :stream_closed, ^conn, ^stream_id} ->
        {:error, :stream_closed}
    after
      timeout -> {:error, :timeout}
    end
  end

  defp stop_if_alive(pid) when is_pid(pid) do
    if Process.alive?(pid), do: GenServer.stop(pid)
  catch
    :exit, _reason -> :ok
  end
end
