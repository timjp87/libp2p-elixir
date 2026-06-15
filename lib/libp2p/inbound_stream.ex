defmodule Libp2p.InboundStream do
  @moduledoc """
  Generic inbound stream responder for direct `ConnectionV2` handlers.

  This helper is intentionally lower-level than `Libp2p.Swarm`: it can be started
  by a process that receives `:stream_open` events directly from a connection, then
  it negotiates the stream protocol and handles identify, ping, gossipsub frame
  draining, or a caller-supplied request/response function.
  """

  use GenServer

  alias Libp2p.ConnectionV2, as: Conn
  alias Libp2p.Crypto.PublicKeyPB
  alias Libp2p.Gossipsub.Framing, as: PbFraming
  alias Libp2p.{IdentifyPB, MultistreamSelect, Protocol}

  @ping_payload_size 32

  @gossipsub_protocols MapSet.new([
                         Protocol.gossipsub_1_2(),
                         Protocol.gossipsub_1_1(),
                         Protocol.gossipsub_1_0()
                       ])

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @impl true
  def init(opts) do
    conn = Keyword.fetch!(opts, :conn)
    stream_id = Keyword.fetch!(opts, :stream_id)
    remote_peer_id = Keyword.get(opts, :remote_peer_id, nil)
    handler_fun = Keyword.fetch!(opts, :handler_fun)
    request_complete_fun = Keyword.get(opts, :request_complete_fun, fn _proto, _buf -> :more end)
    identity = Keyword.fetch!(opts, :identity)
    supported = Keyword.fetch!(opts, :supported_protocols)

    claim_stream(conn, stream_id)

    mss = MultistreamSelect.new_responder()
    {out0, mss} = MultistreamSelect.start(mss)
    send_stream(conn, stream_id, out0)

    {:ok,
     %{
       conn: conn,
       stream_id: stream_id,
       remote_peer_id: remote_peer_id,
       handler_fun: handler_fun,
       request_complete_fun: request_complete_fun,
       identity: identity,
       supported: supported,
       mss: mss,
       protocol_id: nil,
       request_buf: <<>>,
       handled?: false
     }}
  end

  @impl true
  def handle_info({:libp2p, :stream_data, conn, stream_id, data}, st)
      when conn == st.conn and stream_id == st.stream_id and is_binary(data) do
    handle_stream_data(data, st)
  end

  def handle_info({:stream_data, data}, st) when is_binary(data) do
    handle_stream_data(data, st)
  end

  def handle_info({:libp2p, :stream_closed, conn, stream_id}, st)
      when conn == st.conn and stream_id == st.stream_id do
    handle_stream_closed(st)
  end

  def handle_info({:libp2p, :stream_closed, conn, stream_id, _peer_id}, st)
      when conn == st.conn and stream_id == st.stream_id do
    handle_stream_closed(st)
  end

  def handle_info(:stream_closed, st), do: handle_stream_closed(st)

  def handle_info(_msg, st), do: {:noreply, st}

  defp handle_stream_data(_data, %{handled?: true} = st), do: {:noreply, st}

  defp handle_stream_data(data, %{protocol_id: nil} = st) do
    {events, out, mss} = MultistreamSelect.feed(st.mss, data, st.supported)
    send_stream(st.conn, st.stream_id, out)

    protocol_id =
      case Enum.find(events, &match?({:selected, _}, &1)) do
        {:selected, proto} -> proto
        _ -> nil
      end

    st = %{
      st
      | mss: mss,
        protocol_id: protocol_id,
        request_buf: st.request_buf <> Map.get(mss, :buf, <<>>)
    }

    if is_binary(protocol_id) do
      {:noreply, maybe_handle_interactive_protocol(st)}
    else
      {:noreply, st}
    end
  end

  defp handle_stream_data(data, st) do
    st = %{st | request_buf: st.request_buf <> data}
    {:noreply, maybe_handle_interactive_protocol(st)}
  end

  defp handle_stream_closed(st) do
    cond do
      st.handled? ->
        {:stop, :normal, st}

      st.protocol_id in [Protocol.identify(), Protocol.identify_push()] ->
        {:stop, :normal, st}

      st.protocol_id == nil ->
        {:stop, :normal, st}

      st.protocol_id == Protocol.ping() ->
        close_stream(st.conn, st.stream_id)
        {:stop, :normal, st}

      gossipsub_protocol?(st.protocol_id) ->
        close_stream(st.conn, st.stream_id)
        {:stop, :normal, st}

      true ->
        _st = handle_req_resp_request(st, st.request_buf, <<>>)
        {:stop, :normal, st}
    end
  end

  defp maybe_handle_interactive_protocol(%{protocol_id: proto} = st) do
    cond do
      proto in [Protocol.identify(), Protocol.identify_push()] ->
        maybe_handle_identify(st)

      proto == Protocol.ping() ->
        echo_ping_payloads(st)

      gossipsub_protocol?(proto) ->
        drain_gossipsub_frames(st)

      true ->
        maybe_handle_req_resp(st)
    end
  end

  defp maybe_handle_req_resp(%{handled?: true} = st), do: st

  defp maybe_handle_req_resp(%{protocol_id: proto, request_buf: buf} = st)
       when is_binary(proto) do
    case st.request_complete_fun.(proto, buf) do
      {:complete, request, rest} when is_binary(request) and is_binary(rest) ->
        handle_req_resp_request(st, request, rest)

      :complete ->
        handle_req_resp_request(st, buf, <<>>)

      true ->
        handle_req_resp_request(st, buf, <<>>)

      _ ->
        st
    end
  rescue
    _exception -> st
  end

  defp maybe_handle_req_resp(st), do: st

  defp handle_req_resp_request(st, request, rest) when is_binary(request) and is_binary(rest) do
    resp = st.handler_fun.(st.protocol_id, request)

    if resp != nil and resp != <<>>, do: send_stream(st.conn, st.stream_id, resp)
    close_stream(st.conn, st.stream_id)
    %{st | request_buf: rest, handled?: true}
  end

  defp maybe_handle_identify(%{protocol_id: proto} = st) when proto == "/ipfs/id/1.0.0" do
    id_msg = build_identify(st)
    send_stream(st.conn, st.stream_id, PbFraming.encode(IdentifyPB.encode(id_msg)))
    close_stream(st.conn, st.stream_id)
    st
  end

  defp maybe_handle_identify(%{protocol_id: proto} = st) when proto == "/ipfs/id/push/1.0.0" do
    close_stream(st.conn, st.stream_id)
    st
  end

  defp maybe_handle_identify(st), do: st

  defp echo_ping_payloads(st) do
    {payloads, rest} = take_ping_payloads(st.request_buf, [])
    Enum.each(payloads, &send_stream(st.conn, st.stream_id, &1))
    %{st | request_buf: rest}
  end

  defp take_ping_payloads(buf, acc) when byte_size(buf) >= @ping_payload_size do
    <<payload::binary-size(@ping_payload_size), rest::binary>> = buf
    take_ping_payloads(rest, [payload | acc])
  end

  defp take_ping_payloads(rest, acc), do: {Enum.reverse(acc), rest}

  defp drain_gossipsub_frames(st) do
    {_frames, rest} = PbFraming.decode_all(st.request_buf)
    %{st | request_buf: rest}
  end

  defp gossipsub_protocol?(proto) when is_binary(proto),
    do: MapSet.member?(@gossipsub_protocols, proto)

  defp gossipsub_protocol?(_proto), do: false

  defp build_identify(st) do
    public_key = PublicKeyPB.encode_public_key(:secp256k1, st.identity.pubkey_compressed)

    %{
      protocol_version: "ipfs/0.1.0",
      agent_version: "libp2p-elixir/0.1.0",
      public_key: public_key,
      listen_addrs: [],
      observed_addr: nil,
      protocols: MapSet.to_list(st.supported)
    }
  end

  defp claim_stream(conn, stream_id) do
    _ = Conn.set_stream_handler(conn, stream_id, self())
    :ok
  catch
    :exit, _reason -> :ok
  end

  defp send_stream(_conn, _stream_id, <<>>), do: :ok

  defp send_stream(conn, stream_id, data) when is_binary(data) do
    _ = Conn.send_stream(conn, stream_id, data)
    :ok
  catch
    :exit, _reason -> :ok
  end

  defp close_stream(conn, stream_id) do
    _ = Conn.close_stream(conn, stream_id)
    :ok
  catch
    :exit, _reason -> :ok
  end
end
