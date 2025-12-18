defmodule Libp2p.InboundStream do
  @moduledoc """
  Behaviour for handling inbound Libp2p streams.

  Modules implementing this behaviour are used to handle incoming streams for specific
  protocols (like `/ipfs/id/1.0.0` or custom application protocols).

  ## Usage

  When a remote peer initiates a new stream, the `Libp2p.ConnectionV2` process negotiates
  the protocol using Multistream-select. If a handler is registered for the agreed-upon
  protocol, its `handle_stream/2` callback is invoked.

  The handler receives:
  - The `connection` pid (to send data back).
  - The `stream_id` (identifying the specific Yamux stream).
  """

  use GenServer

  require Logger

  alias Libp2p.{IdentifyPB, MultistreamSelect, Protocol}
  alias Libp2p.Gossipsub.Framing, as: PbFraming
  alias Libp2p.Crypto.PublicKeyPB
  alias Libp2p.ConnectionV2, as: Conn

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @impl true
  def init(opts) do
    conn = Keyword.fetch!(opts, :conn)
    stream_id = Keyword.fetch!(opts, :stream_id)
    remote_peer_id = Keyword.get(opts, :remote_peer_id, nil)
    handler_fun = Keyword.fetch!(opts, :handler_fun)
    identity = Keyword.fetch!(opts, :identity)
    supported = Keyword.fetch!(opts, :supported_protocols)

    mss = MultistreamSelect.new_responder()
    {out0, mss} = MultistreamSelect.start(mss)
    if out0 != <<>> do
      try do
        Conn.send_stream(conn, stream_id, out0)
      catch
        :exit, _ -> :ok
      end
    end

    {:ok,
     %{
       conn: conn,
       stream_id: stream_id,
       remote_peer_id: remote_peer_id,
       handler_fun: handler_fun,
       identity: identity,
       supported: supported,
       mss: mss,
       protocol_id: nil,
       request_buf: <<>>
     }}
  end

  @impl true
  def handle_info({:stream_data, data}, st) when is_binary(data) do
    if st.protocol_id == nil do
      {events, out, mss2} = MultistreamSelect.feed(st.mss, data, st.supported)
      if out != <<>> do
        try do
          Conn.send_stream(st.conn, st.stream_id, out)
        catch
          :exit, _ -> :ok
        end
      end

      proto =
        case Enum.find(events, fn e -> match?({:selected, _}, e) end) do
          {:selected, p} -> p
          _ -> nil
        end

      leftover = Map.get(mss2, :buf, <<>>)
      st2 = %{st | mss: mss2, protocol_id: proto, request_buf: st.request_buf <> leftover}

      if is_binary(proto) and proto != nil do
        st2 = maybe_handle_identify(st2)
        if st2.protocol_id in [Protocol.identify(), Protocol.identify_push()] do
          {:noreply, st2}
        else
          # For other protocols, let the handler take over or wait for more data/close.
          {:noreply, st2}
        end
      else
        {:noreply, st2}
      end
    else
      st = %{st | request_buf: st.request_buf <> data}
      st = maybe_handle_identify(st)
      {:noreply, st}
    end
  end

  def handle_info(:stream_closed, st) do
    cond do
      st.protocol_id in [Protocol.identify(), Protocol.identify_push()] ->
        {:stop, :normal, st}

      st.protocol_id == nil ->
        {:stop, :normal, st}

      true ->
        # General purpose handler for other protocols on close.
        # This matches the Eth2 req-resp pattern where we read til EOF.
        resp = st.handler_fun.(st.protocol_id, st.request_buf)
        if resp != nil and resp != <<>> do
          try do
            :ok = Conn.send_stream(st.conn, st.stream_id, resp)
            :ok = Conn.close_stream(st.conn, st.stream_id)
          catch
            :exit, _ -> :ok
          end
        end
        {:stop, :normal, st}
    end
  end

  defp maybe_handle_identify(%{protocol_id: proto} = st) when proto == "/ipfs/id/1.0.0" do
    id_msg = build_identify(st)
    try do
      _ = Conn.send_stream(st.conn, st.stream_id, PbFraming.encode(IdentifyPB.encode(id_msg)))
      _ = Conn.close_stream(st.conn, st.stream_id)
    catch
      :exit, _ -> :ok
    end
    st
  end

  defp maybe_handle_identify(%{protocol_id: proto} = st) when proto == "/ipfs/id/push/1.0.0" do
    try do
      _ = Conn.close_stream(st.conn, st.stream_id)
    catch
      :exit, _ -> :ok
    end
    st
  end

  defp maybe_handle_identify(st), do: st

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
end
