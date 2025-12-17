defmodule Libp2p.RequestResponse do
  @moduledoc """
  Minimal request-response protocol support (Eth2-oriented hooks).

  Design:
  - Swarm routes inbound streams based on the selected protocol id.
  - This module dispatches to a registered handler per protocol id.
  - Concurrency limiting is provided via `Libp2p.ReqRespServer`.

  The byte-level framing and encoding is pluggable via a codec `{encode, decode}`.
  By default, we use `Libp2p.RequestResponse.Framing` (uvarint length prefix).
  """

  use GenServer

  alias Libp2p.{Connection, ReqRespServer}
  alias Libp2p.RequestResponse.Framing

  @type proto_id :: binary()
  @type codec :: {encode :: (binary() -> binary()), decode :: (binary() -> {:ok, binary(), binary()} | :more)}

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    handlers = Keyword.get(opts, :handlers, %{})
    server = Keyword.get(opts, :concurrency_server, ReqRespServer)
    codec = Keyword.get(opts, :codec, default_codec())

    if Keyword.has_key?(opts, :name) and name == nil do
      GenServer.start_link(__MODULE__, %{handlers: handlers, concurrency_server: server, codec: codec})
    else
      GenServer.start_link(__MODULE__, %{handlers: handlers, concurrency_server: server, codec: codec}, name: name)
    end
  end

  @doc """
  Register a handler for a protocol id.

  Handler signature: `(peer_id, request_bytes) -> response_bytes`.
  """
  @spec register(pid() | atom(), proto_id(), (binary(), binary() -> binary())) :: :ok
  def register(rr, proto, fun) when is_binary(proto) and is_function(fun, 2) do
    GenServer.call(rr, {:register, proto, fun})
  end

  @doc """
  Swarm stream router hook (requires Swarm to pass `proto` in).
  """
  @spec handle_inbound(pid(), non_neg_integer(), proto_id(), binary()) :: :ok
  def handle_inbound(conn, stream_id, proto, initial) do
    handle_inbound(__MODULE__, conn, stream_id, proto, initial)
  end

  @spec handle_inbound(pid() | atom(), pid(), non_neg_integer(), proto_id(), binary()) :: :ok
  def handle_inbound(rr, conn, stream_id, proto, initial) do
    GenServer.cast(rr, {:inbound, conn, stream_id, proto, initial || <<>>})
  end

  @doc """
  Perform an outbound request over a connection.
  """
  @spec request(pid() | atom(), pid(), proto_id(), binary(), keyword()) :: {:ok, binary()} | {:error, term()}
  def request(rr, conn, proto, req_bytes, opts \\ []) when is_binary(proto) and is_binary(req_bytes) do
    timeout = Keyword.get(opts, :timeout, 10_000)
    codec = Keyword.get(opts, :codec, nil)
    GenServer.call(rr, {:request, conn, proto, req_bytes, codec, timeout}, timeout + 1_000)
  end

  @impl true
  def init(st), do: {:ok, st}

  @impl true
  def handle_call({:register, proto, fun}, _from, st) do
    {:reply, :ok, %{st | handlers: Map.put(st.handlers, proto, fun)}}
  end

  def handle_call({:request, conn, proto, req_bytes, codec_override, timeout}, _from, st) do
    codec = codec_override || st.codec

    with :ok <- Connection.await_ready(conn, timeout),
         {:ok, stream_id} <- Connection.open_stream(conn),
         {:ok, selected, _initial} <-
           Libp2p.StreamNegotiator.negotiate_outbound(conn, stream_id, [proto], MapSet.new([proto]), timeout: timeout),
         true <- selected == proto,
         :ok <- Connection.stream_send(conn, stream_id, encode(codec, req_bytes)),
         {:ok, resp} <- recv_one(conn, stream_id, codec, timeout) do
      _ = Connection.stream_close(conn, stream_id)
      {:reply, {:ok, resp}, st}
    else
      {:error, reason} -> {:reply, {:error, reason}, st}
      false -> {:reply, {:error, :unexpected_protocol}, st}
      other -> {:reply, {:error, other}, st}
    end
  end

  @impl true
  def handle_cast({:inbound, conn, stream_id, proto, initial}, st) do
    server = self()
    Task.start(fn -> inbound_task(server, st, conn, stream_id, proto, initial) end)
    {:noreply, st}
  end

  # --- inbound ---

  defp inbound_task(_server, st, conn, stream_id, proto, initial) do
    # Read one request, respond once, then close.
    peer_id =
      case Connection.remote_peer_id(conn) do
        {:ok, pid} -> pid
        _ -> <<>>
      end

    case Map.get(st.handlers, proto) do
      nil ->
        _ = Connection.stream_close(conn, stream_id)
        :ok

      handler_fun ->
        with {:ok, req} <- recv_one(conn, stream_id, st.codec, 10_000, initial) do
          # Gate concurrency by {peer, proto}
          key = {peer_id, proto}

          reply =
            ReqRespServer.handle(
              st.concurrency_server,
              key,
              req,
              fn request_bytes -> handler_fun.(peer_id, request_bytes) end,
              max_concurrent: 2,
              timeout: 10_000
            )

          case reply do
            {:ok, resp_bytes} ->
              _ = Connection.stream_send(conn, stream_id, encode(st.codec, resp_bytes))
              _ = Connection.stream_close(conn, stream_id)
              :ok

            {:error, _} ->
              _ = Connection.stream_close(conn, stream_id)
              :ok
          end
        else
          _ -> _ = Connection.stream_close(conn, stream_id)
        end
    end
  end

  # --- framing helpers ---

  defp default_codec do
    {
      fn b -> Framing.encode(b) end,
      fn buf ->
        case Framing.decode_one(buf) do
          :more -> :more
          {msg, rest} -> {:ok, msg, rest}
        end
      end
    }
  end

  defp encode({enc, _dec}, bytes), do: enc.(bytes)

  defp recv_one(conn, stream_id, {_enc, dec}, timeout, initial \\ <<>>) do
    do_recv_one(conn, stream_id, dec, timeout, initial)
  end

  defp do_recv_one(conn, stream_id, dec, timeout, buf) do
    case dec.(buf) do
      {:ok, msg, _rest} ->
        {:ok, msg}

      :more ->
        case Connection.stream_recv(conn, stream_id, timeout) do
          {:ok, data} -> do_recv_one(conn, stream_id, dec, timeout, buf <> data)
          {:error, reason} -> {:error, reason}
        end
    end
  end
end
