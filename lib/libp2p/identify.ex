defmodule Libp2p.Identify do
  @moduledoc """
  Implements the `/ipfs/id/1.0.0` and `/ipfs/id/push/1.0.0` protocols.

  The Identify protocol is used to exchange information about peers, including their public keys,
  listening addresses, and supported protocols.

  ## Protocol Variants

  - **Identify** (`/ipfs/id/1.0.0`): A query-response protocol where one peer asks for the other's
    identity. The response contains the `Identify` protobuf message.
  - **Identify Push** (`/ipfs/id/push/1.0.0`): A one-way stream used to proactively notify connected
    peers of changes (e.g., a new listening address).

  ## Message Content

  The exchanged `Identify` message includes:
  - **protocolVersion**: Family of protocols (e.g., `ipfs/0.1.0`).
  - **agentVersion**: The client implementation (e.g., `libp2p-elixir/0.1.0`).
  - **publicKey**: The public key of the peer.
  - **listenAddrs**: A list of multiaddresses the peer is listening on.
  - **observedAddr**: The address of the remote peer as seen by the sender (useful for NAT detection).
  - **protocols**: A list of protocol IDs supported by the peer.
  """

  alias Libp2p.{ConnectionV2, IdentifyPB, Multiaddr, MultistreamSelect, PeerInfo, PeerStore, Protocol}
  alias Libp2p.Crypto.PublicKeyPB
  alias Libp2p.Gossipsub.Framing

  @default_protocol_version "ipfs/0.1.0"
  @default_agent_version "libp2p-elixir/0.1.0"

  @doc """
  Handle an inbound identify stream.
  """
  @spec handle_inbound(pid(), non_neg_integer(), binary(), binary()) :: :ok | {:error, term()}
  def handle_inbound(conn, stream_id, proto, initial_bytes) when is_binary(proto) do
    cond do
      proto == Protocol.identify() ->
        id_msg = build_local_identify(conn)
        _ = ConnectionV2.send_stream(conn, stream_id, Framing.encode(IdentifyPB.encode(id_msg)))
        _ = ConnectionV2.close_stream(conn, stream_id)
        :ok

      proto == Protocol.identify_push() ->
        peer_store = ConnectionV2.peer_store(conn)

        case recv_one(conn, stream_id, initial_bytes || <<>>, 20_000) do
          {:ok, msg_bytes} ->
            msg = IdentifyPB.decode(msg_bytes)
            _ = ConnectionV2.close_stream(conn, stream_id)
            _ = update_peer_store(conn, peer_store, msg)
            :ok

          {:error, reason} ->
            _ = ConnectionV2.close_stream(conn, stream_id)
            {:error, reason}
        end

      true ->
        _ = ConnectionV2.close_stream(conn, stream_id)
        {:error, :unsupported_identify_protocol}
    end
  end

  @spec handle_inbound(pid(), non_neg_integer(), binary()) :: :ok
  def handle_inbound(conn, stream_id, initial_bytes) do
    handle_inbound(conn, stream_id, Protocol.identify(), initial_bytes || <<>>)
    :ok
  end

  @doc """
  Perform an outbound identify request.
  """
  @spec request(pid(), pid() | atom(), keyword()) :: :ok | {:error, term()}
  def request(conn, peer_store, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 20_000)
    # Eager MSS: send header + proposal in one go
    st = MultistreamSelect.new_initiator([Protocol.identify()])
    {out0, st} = MultistreamSelect.start(st)

    with {:ok, stream_id} <- ConnectionV2.open_stream(conn, out0),
         {:ok, leftover} <- negotiate(conn, stream_id, st, timeout),
         {:ok, msg_bytes} <- recv_one(conn, stream_id, leftover, timeout) do
      msg = IdentifyPB.decode(msg_bytes)
      _ = ConnectionV2.close_stream(conn, stream_id)
      update_peer_store(conn, peer_store, msg)
    end
  end

  defp negotiate(conn, stream_id, st, timeout) do
    receive do
      {:libp2p, :stream_data, ^conn, ^stream_id, data} ->
        {events, out, st2} = MultistreamSelect.feed(st, data, MapSet.new())
        if out != <<>>, do: :ok = ConnectionV2.send_stream(conn, stream_id, out)

        case Enum.find(events, fn e -> match?({:error, _}, e) end) do
          {:error, reason} -> {:error, {:negotiation_failed, reason}}
          _ ->
            case Enum.find(events, fn e -> match?({:selected, _}, e) end) do
              {:selected, _} -> {:ok, Map.get(st2, :buf, <<>>)}
              _ -> negotiate(conn, stream_id, st2, timeout)
            end
        end

      {:libp2p, :stream_closed, ^conn, ^stream_id} ->
        {:error, :stream_closed}
    after
      timeout -> {:error, :timeout}
    end
  end

  defp recv_one(conn, stream_id, buf, timeout) do
    case Framing.decode_one(buf) do
      :more ->
        receive do
          {:libp2p, :stream_data, ^conn, ^stream_id, data} ->
            recv_one(conn, stream_id, buf <> data, timeout)

          {:libp2p, :stream_closed, ^conn, ^stream_id} ->
            {:error, :stream_closed}
        after
          timeout -> {:error, :timeout}
        end

      {msg, _rest} ->
        {:ok, msg}
    end
  end

  defp build_local_identify(conn) do
    local_identity = get_local_identity(conn)
    public_key = PublicKeyPB.encode_public_key(:secp256k1, local_identity.pubkey_compressed)

    %{
      protocol_version: @default_protocol_version,
      agent_version: @default_agent_version,
      public_key: public_key,
      listen_addrs: [],
      observed_addr: nil,
      protocols: []
    }
  end

  defp update_peer_store(conn, peer_store, msg) do
    {:ok, remote_peer_id} = ConnectionV2.remote_peer_id(conn)

    addrs = Enum.map(msg.listen_addrs, &Multiaddr.from_bytes/1)
    observed = if msg.observed_addr, do: Multiaddr.from_bytes(msg.observed_addr)

    info = %PeerInfo{
      peer_id: remote_peer_id,
      addrs: addrs,
      protocols: MapSet.new(msg.protocols || []),
      agent_version: msg.agent_version,
      protocol_version: msg.protocol_version,
      observed_addr: observed,
      last_seen_ms: System.system_time(:millisecond)
    }

    PeerStore.upsert(peer_store, info)
  end

  defp get_local_identity(conn) do
    GenServer.call(conn, :__local_identity__)
  rescue
    _ -> %Libp2p.Identity{}
  end
end
