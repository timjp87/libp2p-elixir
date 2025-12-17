defmodule Libp2p.Identify do
  @moduledoc """
  Identify protocol (`/ipfs/id/1.0.0`) handler.

  Minimal behavior:
  - inbound identify stream: send our Identify message and close
  - outbound identify request: open stream, read Identify message, update PeerStore
  """

  alias Libp2p.{Connection, IdentifyPB, Multiaddr, PeerInfo, PeerStore, Protocol, StreamNegotiator}
  alias Libp2p.Crypto.PublicKeyPB
  alias Libp2p.Gossipsub.Framing

  @default_protocol_version "ipfs/0.1.0"
  @default_agent_version "panacea-libp2p-elixir/0.1.0"

  @doc """
  Swarm stream router hook.

  Called after multistream-select has already selected a protocol on this stream.

  - For `/ipfs/id/1.0.0`: we are the responder and **send** our Identify info.
  - For `/ipfs/id/push/1.0.0`: we are the responder and **receive** the push update.
  """
  @spec handle_inbound(pid(), non_neg_integer(), binary(), binary()) :: :ok | {:error, term()}
  def handle_inbound(conn, stream_id, proto, initial_bytes) when is_binary(proto) do
    cond do
      proto == Protocol.identify() ->
        id_msg = build_local_identify(conn)
        _ = Connection.stream_send(conn, stream_id, Framing.encode(IdentifyPB.encode(id_msg)))
        _ = Connection.stream_close(conn, stream_id)
        :ok

      proto == Protocol.identify_push() ->
        peer_store = Connection.peer_store(conn)

        case recv_one(conn, stream_id, initial_bytes || <<>>, 20_000) do
          {:ok, msg_bytes} ->
            msg = IdentifyPB.decode(msg_bytes)
            _ = Connection.stream_close(conn, stream_id)
            _ = update_peer_store(conn, peer_store, msg)
            :ok

          {:error, reason} ->
            _ = Connection.stream_close(conn, stream_id)
            {:error, reason}
        end

      true ->
        _ = Connection.stream_close(conn, stream_id)
        {:error, :unsupported_identify_protocol}
    end
  end

  @spec handle_inbound(pid(), non_neg_integer(), binary()) :: :ok
  def handle_inbound(conn, stream_id, initial_bytes) do
    _ = initial_bytes
    handle_inbound(conn, stream_id, Protocol.identify(), <<>>)
    :ok
  end

  @doc """
  Perform an outbound identify request (we open the stream and read their Identify info).
  """
  @spec request(pid(), pid() | atom()) :: :ok | {:error, term()}
  def request(conn, peer_store) do
    with {:ok, stream_id} <- Connection.open_stream(conn) |> tag_err(:open_stream),
         {:ok, proto, initial} <-
           StreamNegotiator.negotiate_outbound(conn, stream_id, [Protocol.identify()], MapSet.new([Protocol.identify()]),
             timeout: 20_000
           )
           |> tag_err(:negotiate),
         true <- proto == Protocol.identify() do
      case recv_one(conn, stream_id, initial || <<>>, 20_000) do
        {:ok, msg_bytes} ->
          msg = IdentifyPB.decode(msg_bytes)
          _ = Connection.stream_close(conn, stream_id)
          update_peer_store(conn, peer_store, msg)

        {:error, reason} ->
          {:error, {:recv_identify, reason}}
      end
    else
      {:error, reason} -> {:error, reason}
      false -> {:error, :unexpected_protocol}
    end
  end

  defp tag_err({:ok, _} = ok, _tag), do: ok
  defp tag_err({:ok, _a, _b} = ok, _tag), do: ok
  defp tag_err({:error, reason}, tag), do: {:error, {tag, reason}}

  defp recv_one(conn, stream_id, buf, timeout) do
    case Framing.decode_one(buf) do
      :more ->
        case Connection.stream_recv(conn, stream_id, timeout) do
          {:ok, data} -> recv_one(conn, stream_id, buf <> data, timeout)
          {:error, reason} -> {:error, {:recv_failed, reason, buf_bytes: byte_size(buf)}}
        end

      {msg, _rest} ->
        {:ok, msg}
    end
  end

  defp build_local_identify(conn) do
    # TODO: plumb listen addrs + supported protocols from Swarm config.
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
    {:ok, remote_peer_id} = Connection.remote_peer_id(conn) |> ok_or_not_ready()

    addrs =
      msg.listen_addrs
      |> Enum.map(&Multiaddr.from_bytes/1)

    observed =
      if msg.observed_addr != nil do
        Multiaddr.from_bytes(msg.observed_addr)
      else
        nil
      end

    info = %PeerInfo{
      peer_id: remote_peer_id,
      addrs: addrs,
      protocols: MapSet.new(msg.protocols || []),
      agent_version: msg.agent_version,
      protocol_version: msg.protocol_version,
      observed_addr: observed,
      last_seen_ms: System.system_time(:millisecond)
    }

    :ok = PeerStore.upsert(peer_store, info)
    :ok
  end

  defp get_local_identity(conn) do
    GenServer.call(conn, :__local_identity__)
  end

  defp ok_or_not_ready({:ok, v}), do: {:ok, v}
  defp ok_or_not_ready({:error, :not_ready}), do: raise(ArgumentError, "connection not ready")
  defp ok_or_not_ready(other), do: other
end
