defmodule Libp2p.RequestResponse do
  @moduledoc """
  Minimal request-response protocol support.
  """

  use GenServer

  alias Libp2p.{ConnectionV2, ReqRespServer}
  alias Libp2p.RequestResponse.Framing

  @type proto_id :: binary()
  @type codec ::
          {encode :: (binary() -> binary()),
           decode :: (binary() -> {:ok, binary(), binary()} | :more)}

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    handlers = Keyword.get(opts, :handlers, %{})
    server = Keyword.get(opts, :concurrency_server, ReqRespServer)
    codec = Keyword.get(opts, :codec, default_codec())

    if Keyword.has_key?(opts, :name) and name == nil do
      GenServer.start_link(__MODULE__, %{
        handlers: handlers,
        concurrency_server: server,
        codec: codec
      })
    else
      GenServer.start_link(
        __MODULE__,
        %{handlers: handlers, concurrency_server: server, codec: codec},
        name: name
      )
    end
  end

  @doc """
  Register a handler for a protocol id.
  """
  @spec register(pid() | atom(), proto_id(), (binary(), binary() -> binary())) :: :ok
  def register(rr, proto, fun) when is_binary(proto) and is_function(fun, 2) do
    GenServer.call(rr, {:register, proto, fun})
  end

  @doc """
  Perform an outbound request over a connection.
  """
  @spec request(pid() | atom(), pid(), proto_id(), binary(), keyword()) ::
          {:ok, binary()} | {:error, term()}
  def request(rr, conn, proto, req_bytes, opts \\ [])
      when is_binary(proto) and is_binary(req_bytes) do
    timeout = Keyword.get(opts, :timeout, 10_000)
    codec = Keyword.get(opts, :codec, nil) || GenServer.call(rr, :get_codec)

    Task.Supervisor.async(Libp2p.RpcStreamSupervisor, fn ->
      do_request(conn, proto, req_bytes, codec, timeout)
    end)
    |> Task.await(timeout + 5000)
  rescue
    _ -> {:error, :request_failed}
  end

  defp do_request(conn, proto, req_bytes, codec, timeout) do
    # Eager MSS: send header + proposal in one go
    mss = Libp2p.MultistreamSelect.new_initiator([proto])
    {out0, mss} = Libp2p.MultistreamSelect.start(mss)

    try do
      with {:ok, stream_id} <- ConnectionV2.open_stream(conn, out0),
           :ok <- ConnectionV2.set_stream_handler(conn, stream_id, self()),
           {:ok, leftover} <- negotiate(conn, stream_id, mss, timeout),
           :ok <- ConnectionV2.send_stream(conn, stream_id, encode(codec, req_bytes)),
           :ok <- ConnectionV2.close_stream(conn, stream_id),
           {:ok, resp} <- recv_one(conn, stream_id, codec, timeout, leftover) do
        {:ok, resp}
      else
        {:error, reason} -> {:error, reason}
        other -> {:error, other}
      end
    catch
      :exit, _reason ->
        {:error, :connection_closed}
    end
  end

  @doc """
  Handle an inbound stream for a registered protocol.
  """
  @spec handle_inbound(pid() | atom(), pid(), non_neg_integer(), proto_id(), binary()) :: :ok
  def handle_inbound(rr, conn, stream_id, proto, initial) do
    case GenServer.call(rr, {:get_handler, proto}) do
      {:ok, handler, codec} ->
        # Framing is handled here by the task
        case recv_one(conn, stream_id, codec, 20_000, initial) do
          {:ok, req_bytes} ->
            peer_id =
              case ConnectionV2.remote_peer_id(conn) do
                {:ok, pid} -> pid
                {:error, _} -> nil
              end

            if is_nil(peer_id) do
              _ = ConnectionV2.reset_stream(conn, stream_id)
              :ok
            else
              resp = handler.(peer_id, req_bytes)
              encoded_resp = encode(codec, resp)
              _ = ConnectionV2.send_stream(conn, stream_id, encoded_resp)
              _ = ConnectionV2.close_stream(conn, stream_id)
              :ok
            end

          {:error, _reason} ->
            _ = ConnectionV2.reset_stream(conn, stream_id)
            :ok
        end

      :error ->
        _ = ConnectionV2.reset_stream(conn, stream_id)
        :ok
    end
  end

  @impl true
  def init(st), do: {:ok, st}

  @impl true
  def handle_info(_msg, st), do: {:noreply, st}

  @impl true
  def handle_call({:register, proto, fun}, _from, st) do
    {:reply, :ok, %{st | handlers: Map.put(st.handlers, proto, fun)}}
  end

  @impl true
  def handle_call(:get_codec, _from, st) do
    {:reply, st.codec, st}
  end

  @impl true
  def handle_call({:get_handler, proto}, _from, st) do
    case Map.fetch(st.handlers, proto) do
      {:ok, fun} -> {:reply, {:ok, fun, st.codec}, st}
      :error -> {:reply, :error, st}
    end
  end

  defp negotiate(conn, stream_id, mss, timeout) do
    receive do
      {:libp2p, :stream_data, ^conn, ^stream_id, data} ->
        {events, out, mss2} = Libp2p.MultistreamSelect.feed(mss, data, MapSet.new())
        if out != <<>>, do: :ok = ConnectionV2.send_stream(conn, stream_id, out)

        case Enum.find(events, fn e -> match?({:error, _}, e) end) do
          {:error, reason} ->
            {:error, {:negotiation_failed, reason}}

          _ ->
            case Enum.find(events, fn e -> match?({:selected, _}, e) end) do
              {:selected, _} -> {:ok, Map.get(mss2, :buf, <<>>)}
              _ -> negotiate(conn, stream_id, mss2, timeout)
            end
        end

      {:libp2p, :stream_closed, ^conn, ^stream_id} ->
        {:error, :stream_closed}
    after
      timeout -> {:error, :timeout}
    end
  end

  defp recv_one(conn, stream_id, {_enc, dec}, timeout, initial) do
    do_recv_one(conn, stream_id, dec, timeout, initial)
  end

  defp do_recv_one(conn, stream_id, dec, timeout, buf) do
    case dec.(buf) do
      {:ok, msg, _rest} ->
        {:ok, msg}

      :more ->
        receive do
          {:libp2p, :stream_data, ^conn, ^stream_id, data} ->
            do_recv_one(conn, stream_id, dec, timeout, buf <> data)

          {:libp2p, :stream_closed, ^conn, ^stream_id} ->
            # Some responders might close after sending the full response
            case dec.(buf) do
              {:ok, msg, _rest} -> {:ok, msg}
              _ -> {:error, :truncated}
            end
        after
          timeout -> {:error, :timeout}
        end
    end
  end

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
end
