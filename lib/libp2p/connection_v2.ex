defmodule Libp2p.ConnectionV2 do
  @moduledoc """
  Manages a secure, multiplexed Libp2p connection.

  This module encapsulates the state machine for a single peer connection, handling the
  transition from a raw transport socket to a fully functional application session.

  ## Connection Lifecycle

  The connection process follows the standard Libp2p upgrade path:

  1.  **Transport Establishment**: A raw TCP connection is established (either via Dial or Listen).
  2.  **Multistream-select (Security)**: The peers negotiate the security protocol.
      Only `/noise` is currently supported.
  3.  **Secure Handshake**: The peers perform a Noise XX handshake to authenticate each other
      and establish shared encryption keys. See `Libp2p.Noise` for details.
  4.  **Multistream-select (Muxer)**: Over the now-encrypted channel, the peers negotiate a
      stream multiplexer. Only `/yamux/1.0.0` is currently supported.
  5.  **Multiplexing (Yamux)**: The process enters the Yamux session mode. It acts as the
      controller for the session, parsing incoming frames and routing them to logical streams.

  ## Stream Management

  Once established, this process manages multiple concurrent logical streams (`Libp2p.InboundStream`
  or task-based handlers). It handles:
  - Opening new outbound streams.
  - Accepting inbound streams and negotiating protocols.
  - Flow control (Yamux window updates).
  - Connection teardown (GoAway frames).
  """

  @behaviour :gen_statem

  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :temporary,
      shutdown: 500
    }
  end

  require Logger

  alias Libp2p.{Identity, MultistreamSelect, Noise, PeerId}
  alias Libp2p.Yamux.Session, as: Yamux

  @sec_proposals ["/noise"]
  @sec_supported MapSet.new(["/noise"])
  @mux_proposals ["/yamux/1.0.0"]
  @mux_supported MapSet.new(["/yamux/1.0.0"])

  @type role :: :initiator | :responder

  @spec start_link(keyword()) :: :gen_statem.start_ret()
  def start_link(opts) do
    :gen_statem.start_link(__MODULE__, opts, [])
  end

  @spec remote_peer_id(pid()) :: {:ok, binary()} | {:error, term()}
  def remote_peer_id(conn), do: :gen_statem.call(conn, :remote_peer_id)

  @spec await_ready(pid(), timeout()) :: :ok | {:error, term()}
  def await_ready(conn, timeout \\ 20_000) do
    :gen_statem.call(conn, :await_ready, timeout)
  end

  @spec open_stream(pid()) :: {:ok, non_neg_integer()} | {:error, term()}
  def open_stream(conn) when is_pid(conn), do: :gen_statem.call(conn, :open_stream, 30_000)

  @spec open_stream(pid(), binary()) :: {:ok, non_neg_integer()} | {:error, term()}
  def open_stream(conn, initial_data) when is_pid(conn) and is_binary(initial_data),
    do: :gen_statem.call(conn, {:open_stream, initial_data}, 30_000)

  @spec send_stream(pid(), non_neg_integer(), binary()) :: :ok | {:error, term()}
  def send_stream(conn, stream_id, data)
      when is_pid(conn) and is_integer(stream_id) and is_binary(data),
      do: :gen_statem.call(conn, {:send_stream, stream_id, data})

  @spec close_stream(pid(), non_neg_integer()) :: :ok | {:error, term()}
  def close_stream(conn, stream_id) when is_pid(conn) and is_integer(stream_id),
    do: :gen_statem.call(conn, {:close_stream, stream_id})

  @spec peer_store(pid()) :: pid() | atom()
  def peer_store(conn), do: :gen_statem.call(conn, :peer_store)

  @doc "Reset (RST) a yamux stream."
  @spec reset_stream(pid() | atom(), non_neg_integer()) :: :ok | {:error, term()}
  def reset_stream(conn, stream_id) do
    :gen_statem.call(conn, {:reset_stream, stream_id})
  end

  @doc "Set the process that will receive stream events."
  @spec set_stream_handler(pid(), non_neg_integer(), pid()) :: :ok
  def set_stream_handler(conn, stream_id, pid) do
    :gen_statem.call(conn, {:set_stream_handler, stream_id, pid})
  end

  @impl :gen_statem
  def callback_mode, do: [:handle_event_function, :state_enter]

  @impl :gen_statem
  def init(opts) do
    role = Keyword.fetch!(opts, :role)
    %Identity{} = identity = Keyword.fetch!(opts, :identity)
    handler = Keyword.get(opts, :handler, nil)
    notify_conn_ready? = Keyword.get(opts, :notify_conn_ready?, false)
    expected_peer_id = Keyword.get(opts, :expected_peer_id, nil)
    enforce_expected_peer_id? = Keyword.get(opts, :enforce_expected_peer_id?, true)
    peer_store = Keyword.get(opts, :peer_store, Libp2p.PeerStore)

    dial_timeout_ms = Keyword.get(opts, :dial_timeout_ms, 3_000)
    noise_prologue = Keyword.get(opts, :noise_prologue, <<>>)
    noise_hash_protocol_name? = Keyword.get(opts, :noise_hash_protocol_name?, false)
    noise_hkdf_swap? = Keyword.get(opts, :noise_hkdf_swap?, false)
    noise_nonce_be? = Keyword.get(opts, :noise_nonce_be?, false)

    {socket_info, _initial_phase, socket_opts} =
      case role do
        :initiator ->
          {ip, port} = Keyword.fetch!(opts, :dial)
          {{:outbound, nil, {ip, port}}, :connecting, []}

        :responder ->
          sock = Keyword.fetch!(opts, :socket)
          {:ok, {ip, port}} = :inet.peername(sock)
          {{:inbound, sock, {ip, port}}, :mss_security, [active: :once]}
      end

    {_dir, sock, peer_addr} = socket_info
    if is_port(sock), do: :ok = :inet.setopts(sock, socket_opts)

    Logger.debug(%{
      event: "p2p_conn_init",
      role: role,
      peer_addr: inspect(peer_addr),
      expected_peer_id: expected_peer_id
    })

    mss =
      case role do
        :initiator -> MultistreamSelect.new_initiator(@sec_proposals)
        :responder -> MultistreamSelect.new_responder()
      end

    noise =
      Noise.new(
        if(role == :initiator, do: :initiator, else: :responder),
        identity,
        noise_prologue,
        noise_hash_protocol_name?,
        noise_hkdf_swap?,
        noise_nonce_be?
      )

    data = %{
      role: role,
      sock: sock,
      peer_addr: peer_addr,
      handler: handler,
      notify_conn_ready?: notify_conn_ready?,
      identity: identity,
      expected_peer_id: expected_peer_id,
      enforce_expected_peer_id?: enforce_expected_peer_id?,
      remote_peer_id: nil,
      peer_store: peer_store,
      notify_ready: Keyword.get(opts, :notify_ready),
      mss_state: mss,
      dial_timeout_ms: dial_timeout_ms,
      buf: <<>>,
      noise: noise,
      noise_buf: <<>>,
      noise_stage: nil,
      noise_out: nil,
      noise_in: nil,
      noise_prologue: noise_prologue,
      noise_hash_protocol_name?: noise_hash_protocol_name?,
      noise_hkdf_swap?: noise_hkdf_swap?,
      noise_nonce_be?: noise_nonce_be?,
      mux_mss_state: nil,
      yamux: nil,
      yamux_stream_owners: %{},
      yamux_stream_buffers: %{},
      yamux_stream_waiters: %{},
      ready_waiters: []
    }

    if role == :initiator do
      {:ok, :connecting, data, [{:next_event, :internal, :connect}]}
    else
      {out, mss} = MultistreamSelect.start(data.mss_state)
      if out != <<>>, do: :ok = :gen_tcp.send(sock, out)
      {:ok, :mss_security, %{data | mss_state: mss}}
    end
  end

  @impl :gen_statem
  def handle_event(:enter, _old, :connecting, _data) do
    :keep_state_and_data
  end

  @impl :gen_statem
  def handle_event(:internal, :connect, :connecting, data) do
    %{peer_addr: {ip, port}, dial_timeout_ms: timeout} = data

    case :gen_tcp.connect(
           ip,
           port,
           [:binary, active: :once, packet: 0, nodelay: true, keepalive: true],
           timeout
         ) do
      {:ok, sock} ->
        {out, mss} = MultistreamSelect.start(data.mss_state)
        if out != <<>>, do: :ok = :gen_tcp.send(sock, out)
        {:next_state, :mss_security, %{data | sock: sock, mss_state: mss}}

      {:error, reason} ->
        {:stop, {:shutdown, {:dial_failed, {ip, port}, reason}}}
    end
  end

  @impl :gen_statem
  def handle_event(:enter, _old_state, :mss_security, _data) do
    # Logic is handled in init or transitioned to with actions
    :keep_state_and_data
  end

  @impl :gen_statem
  def handle_event(:info, {:tcp, sock, bin}, _state, %{sock: sock} = data) do
    :ok = :inet.setopts(sock, active: :once)
    {:keep_state, %{data | buf: data.buf <> bin}, [{:next_event, :internal, :drive}]}
  end

  @impl :gen_statem
  def handle_event(:internal, :drive, :mss_security, data) do
    {events, out, mss2} = MultistreamSelect.feed(data.mss_state, data.buf, @sec_supported)
    if out != <<>>, do: _ = :gen_tcp.send(data.sock, out)
    data = %{data | mss_state: mss2, buf: mss2.buf}

    case Enum.find(events, fn e -> match?({:selected, _}, e) end) do
      {:selected, "/noise"} ->
        {:next_state, :noise, %{data | noise_buf: data.buf, buf: <<>>},
         [{:next_event, :internal, :drive}]}

      _ ->
        {:keep_state, data}
    end
  end

  @impl :gen_statem
  def handle_event(:enter, _old_state, :noise, data) do
    data = start_noise(data)
    {:keep_state, data}
  end

  @impl :gen_statem
  def handle_event(:internal, :drive, :noise, data) do
    data = %{data | noise_buf: data.noise_buf <> data.buf, buf: <<>>}

    case drive_noise(data) do
      {:ok, data} -> {:keep_state, data}
      {:finish, data} -> finish_noise(data)
      {:error, reason} -> {:stop, {:shutdown, reason}}
    end
  end

  @impl :gen_statem
  def handle_event(:enter, _old, :mss_muxer, _data) do
    :keep_state_and_data
  end

  @impl :gen_statem
  def handle_event(:internal, :drive, :mss_muxer, data) do
    data = %{data | noise_buf: data.noise_buf <> data.buf, buf: <<>>}

    case drive_noise_transport(data) do
      {:ok, data} -> {:keep_state, data}
      {:error, reason} -> {:stop, {:shutdown, reason}}
    end
  end

  @impl :gen_statem
  def handle_event(:internal, :drive, :yamux, data) do
    data = %{data | noise_buf: data.noise_buf <> data.buf, buf: <<>>}

    case drive_noise_transport(data) do
      {:ok, data} -> {:keep_state, data}
      {:error, reason} -> {:stop, {:shutdown, reason}}
    end
  end

  @impl :gen_statem
  def handle_event(:enter, _old, :yamux, _data) do
    :keep_state_and_data
  end

  @impl :gen_statem
  def handle_event(:info, {:tcp_closed, sock}, _state, %{sock: sock} = data) do
    cleanup_and_stop(data, :normal)
  end

  @impl :gen_statem
  def handle_event(:info, {:tcp_error, sock, reason}, _state, %{sock: sock} = data) do
    cleanup_and_stop(data, reason)
  end

  @impl :gen_statem
  def handle_event(:info, :start_socket, _state, data) do
    :ok = :inet.setopts(data.sock, active: :once)
    {:keep_state, data, [{:next_event, :internal, :drive}]}
  end

  # Synchronous calls
  @impl :gen_statem
  def handle_event({:call, from}, :remote_peer_id, _state, data) do
    {:keep_state, data, [{:reply, from, {:ok, data.remote_peer_id}}]}
  end

  @impl :gen_statem
  def handle_event({:call, from}, :peer_store, _state, data) do
    {:keep_state, data, [{:reply, from, data.peer_store}]}
  end

  @impl :gen_statem
  def handle_event({:call, from}, :__local_identity__, _state, data) do
    {:keep_state, data, [{:reply, from, data.identity}]}
  end

  @impl :gen_statem
  def handle_event({:call, from}, :await_ready, state, data) do
    if state == :yamux do
      {:keep_state, data, [{:reply, from, :ok}]}
    else
      {:keep_state, %{data | ready_waiters: [from | data.ready_waiters]}}
    end
  end

  @impl :gen_statem
  def handle_event({:call, from}, :open_stream, :yamux, data) do
    {id, out, y2} = Yamux.open_stream(data.yamux)
    {from_pid, _} = from

    data = %{
      data
      | yamux: y2,
        yamux_stream_owners: Map.put(data.yamux_stream_owners, id, from_pid)
    }

    data = send_transport(data, out)
    {:keep_state, data, [{:reply, from, {:ok, id}}]}
  end

  @impl :gen_statem
  def handle_event({:call, from}, {:open_stream, initial_data}, :yamux, data) do
    {id, out, y2} = Yamux.open_stream_with_data(data.yamux, initial_data)
    {from_pid, _} = from

    data = %{
      data
      | yamux: y2,
        yamux_stream_owners: Map.put(data.yamux_stream_owners, id, from_pid)
    }

    data = send_transport(data, out)
    {:keep_state, data, [{:reply, from, {:ok, id}}]}
  end

  @impl :gen_statem
  def handle_event({:call, from}, {:send_stream, stream_id, bytes}, :yamux, data) do
    {out, y2} = Yamux.send_data(data.yamux, stream_id, bytes)
    data = %{data | yamux: y2}
    data = send_transport(data, out)
    {:keep_state, data, [{:reply, from, :ok}]}
  rescue
    _ -> {:keep_state, data, [{:reply, from, {:error, :bad_stream}}]}
  end

  @impl :gen_statem
  def handle_event({:call, from}, {:close_stream, stream_id}, :yamux, data) do
    {out, y2} = Yamux.close_stream(data.yamux, stream_id)
    data = %{data | yamux: y2}
    data = send_transport(data, out)
    {:keep_state, data, [{:reply, from, :ok}]}
  rescue
    _ -> {:keep_state, data, [{:reply, from, {:error, :bad_stream}}]}
  end

  @impl :gen_statem
  def handle_event({:call, from}, {:reset_stream, stream_id}, :yamux, data) do
    {out, y2} = Yamux.reset_stream(data.yamux, stream_id)
    data = %{data | yamux: y2}
    data = send_transport(data, out)
    {:keep_state, data, [{:reply, from, :ok}]}
  rescue
    _ -> {:keep_state, data, [{:reply, from, {:error, :bad_stream}}]}
  end

  @impl :gen_statem
  def handle_event({:call, from}, {:stream_send, stream_id, bytes}, :yamux, data) do
    handle_event({:call, from}, {:send_stream, stream_id, bytes}, :yamux, data)
  end

  @impl :gen_statem
  def handle_event({:call, from}, {:stream_close, stream_id}, :yamux, data) do
    handle_event({:call, from}, {:close_stream, stream_id}, :yamux, data)
  end

  @impl :gen_statem
  def handle_event({:call, from}, {:stream_recv, stream_id}, :yamux, data) do
    case Map.get(data.yamux_stream_buffers, stream_id) do
      bytes when is_binary(bytes) and bytes != <<>> ->
        {:keep_state,
         %{data | yamux_stream_buffers: Map.put(data.yamux_stream_buffers, stream_id, <<>>)},
         [{:reply, from, {:ok, bytes}}]}

      _ ->
        waiters = Map.get(data.yamux_stream_waiters, stream_id, [])

        {:keep_state,
         %{
           data
           | yamux_stream_waiters:
               Map.put(data.yamux_stream_waiters, stream_id, waiters ++ [from])
         }}
    end
  end

  @impl :gen_statem
  def handle_event({:call, from}, {:set_stream_handler, stream_id, pid}, :yamux, data) do
    data = %{data | yamux_stream_owners: Map.put(data.yamux_stream_owners, stream_id, pid)}
    # Flush existing buffer to the new owner
    case Map.get(data.yamux_stream_buffers, stream_id, <<>>) do
      <<>> ->
        {:keep_state, data, [{:reply, from, :ok}]}

      bytes ->
        send(pid, {:libp2p, :stream_data, self(), stream_id, bytes})

        {:keep_state,
         %{data | yamux_stream_buffers: Map.put(data.yamux_stream_buffers, stream_id, <<>>)},
         [{:reply, from, :ok}]}
    end
  end

  @impl :gen_statem
  def handle_event({:call, from}, _msg, _state, data) do
    {:keep_state, data, [{:reply, from, {:error, :not_ready}}]}
  end

  # Private Logic
  defp start_noise(%{role: :initiator} = data) do
    {msg1, noise2} = Noise.initiator_msg1(data.noise)
    _ = :gen_tcp.send(data.sock, Noise.frame(msg1))
    %{data | noise: noise2, noise_stage: :wait_msg2}
  end

  defp start_noise(%{role: :responder} = data) do
    %{data | noise_stage: :wait_msg1}
  end

  defp drive_noise(%{noise_stage: :wait_msg1} = data) do
    case Noise.deframe(data.noise_buf) do
      :more ->
        {:ok, data}

      {msg1, rest} ->
        {msg2, noise2} = Noise.responder_msg2(data.noise, msg1)
        _ = :gen_tcp.send(data.sock, Noise.frame(msg2))
        {:ok, %{data | noise: noise2, noise_buf: rest, noise_stage: :wait_msg3}}
    end
  end

  defp drive_noise(%{noise_stage: :wait_msg2} = data) do
    case Noise.deframe(data.noise_buf) do
      :more ->
        {:ok, data}

      {msg2, rest} ->
        try do
          {msg3, noise2, {cs_out, cs_in}} = Noise.initiator_msg3(data.noise, msg2)
          _ = :gen_tcp.send(data.sock, Noise.frame(msg3))
          {:finish, %{data | noise: noise2, noise_out: cs_out, noise_in: cs_in, noise_buf: rest}}
        rescue
          e in ArgumentError -> {:error, {:handshake_failed, Exception.message(e)}}
        end
    end
  end

  defp drive_noise(%{noise_stage: :wait_msg3} = data) do
    case Noise.deframe(data.noise_buf) do
      :more ->
        {:ok, data}

      {msg3, rest} ->
        try do
          {noise2, {cs_in, cs_out}} = Noise.responder_finish(data.noise, msg3)
          {:finish, %{data | noise: noise2, noise_out: cs_out, noise_in: cs_in, noise_buf: rest}}
        rescue
          e in ArgumentError -> {:error, {:handshake_failed, Exception.message(e)}}
        end
    end
  end

  defp finish_noise(data) do
    remote_peer_id = derive_remote_peer_id!(data)

    if data.enforce_expected_peer_id? and is_binary(data.expected_peer_id) and
         data.expected_peer_id != remote_peer_id do
      {:stop, {:shutdown, {:peer_id_mismatch, data.expected_peer_id, remote_peer_id}}}
    else
      data = %{data | remote_peer_id: remote_peer_id}

      case Map.get(data.noise, :selected_stream_muxer, nil) do
        "/yamux/1.0.0" ->
          enter_yamux(data)

        nil ->
          enter_mss_muxer(data)

        other ->
          Logger.warning("unsupported negotiated stream muxer #{inspect(other)}")
          {:keep_state, data}
      end
    end
  end

  defp enter_yamux(data) do
    y = Yamux.new(if(data.role == :initiator, do: :client, else: :server))

    data = %{data | yamux: y, mux_mss_state: nil}
    notify_ready(data)
    {:next_state, :yamux, data, [{:next_event, :internal, :drive}]}
  end

  defp enter_mss_muxer(data) do
    mss =
      case data.role do
        :initiator -> MultistreamSelect.new_initiator(@mux_proposals)
        :responder -> MultistreamSelect.new_responder()
      end

    {out0, mss} = MultistreamSelect.start(mss)
    data = if out0 != <<>>, do: send_transport(data, out0), else: data
    {:next_state, :mss_muxer, %{data | mux_mss_state: mss}, [{:next_event, :internal, :drive}]}
  end

  defp notify_ready(data) do
    if data.notify_conn_ready? and data.handler != nil do
      send(data.handler, {:libp2p, :conn_ready, self(), data.remote_peer_id})
    end

    if data.notify_ready != nil do
      send(data.notify_ready, {:libp2p, :conn_ready, self(), data.remote_peer_id})
    end

    Enum.each(data.ready_waiters, fn from -> :gen_statem.reply(from, :ok) end)
  end

  defp drive_noise_transport(data) do
    case Noise.deframe(data.noise_buf) do
      :more ->
        {:ok, data}

      {ct, rest} ->
        {pt, cs_in} = Noise.transport_decrypt(data.noise_in, ct, <<>>)
        data = %{data | noise_in: cs_in, noise_buf: rest}

        case handle_transport_plaintext(data, pt) do
          {:ok, data} -> drive_noise_transport(data)
          res -> res
        end
    end
  rescue
    _ -> {:ok, data}
  end

  defp handle_transport_plaintext(%{mux_mss_state: mss} = data, bytes) when not is_nil(mss) do
    {events, out, mss2} = MultistreamSelect.feed(mss, bytes, @mux_supported)
    data = %{data | mux_mss_state: mss2}
    data = if out != <<>>, do: send_transport(data, out), else: data

    case Enum.find(events, fn e -> match?({:selected, _}, e) end) do
      {:selected, "/yamux/1.0.0"} ->
        # Transition to yamux state, processing leftovers
        y = Yamux.new(if(data.role == :initiator, do: :client, else: :server))
        leftover = Map.get(mss2, :buf, <<>>)

        data = %{data | yamux: y, mux_mss_state: nil}
        notify_ready(data)

        if leftover != <<>> do
          {:next_state, :yamux, data, [{:next_event, :internal, :drive}]}
        else
          {:next_state, :yamux, data}
        end

      _ ->
        {:ok, data}
    end
  end

  defp handle_transport_plaintext(data, bytes) do
    {events, out, y2} = Yamux.feed(data.yamux, bytes)
    data = %{data | yamux: y2}
    data = if out != <<>>, do: send_transport(data, out), else: data

    data =
      Enum.reduce(events, data, fn event, data_acc ->
        case event do
          {:stream_open, id} ->
            if data_acc.handler != nil do
              send(data_acc.handler, {:libp2p, :stream_open, self(), id, data_acc.remote_peer_id})
            end

            data_acc

          {:stream_data, id, bytes} ->
            case Map.get(data_acc.yamux_stream_owners, id) do
              owner when is_pid(owner) ->
                send(owner, {:libp2p, :stream_data, self(), id, bytes})
                data_acc

              _ ->
                case Map.get(data_acc.yamux_stream_waiters, id) do
                  [from | rest] ->
                    :gen_statem.reply(from, {:ok, bytes})

                    %{
                      data_acc
                      | yamux_stream_waiters: Map.put(data_acc.yamux_stream_waiters, id, rest)
                    }

                  _ ->
                    old_buf = Map.get(data_acc.yamux_stream_buffers, id, <<>>)

                    %{
                      data_acc
                      | yamux_stream_buffers:
                          Map.put(data_acc.yamux_stream_buffers, id, old_buf <> bytes)
                    }
                end
            end

          {:stream_closed, id} ->
            send_to_owner_or_handler(data_acc, id, {:libp2p, :stream_closed, self(), id})
            data_acc

          {:stream_reset, id} ->
            send_to_owner_or_handler(data_acc, id, {:libp2p, :stream_closed, self(), id})
            data_acc

          _ ->
            data_acc
        end
      end)

    {:ok, data}
  end

  defp send_to_owner_or_handler(data, id, msg) do
    case Map.get(data.yamux_stream_owners, id) do
      owner when is_pid(owner) ->
        send(owner, msg)

      _ ->
        if data.handler != nil do
          # Map to handler's expected format if needed
          send(data.handler, put_elem(msg, tuple_size(msg) - 1, data.remote_peer_id))
        end
    end
  end

  defp send_transport(data, plaintext) do
    {ct, cs_out} = Noise.transport_encrypt(data.noise_out, plaintext, <<>>)

    case :gen_tcp.send(data.sock, Noise.frame(ct)) do
      :ok -> %{data | noise_out: cs_out}
      {:error, _} -> data
    end
  end

  defp derive_remote_peer_id!(data) do
    case data.noise.remote_identity_key do
      {:secp256k1, pub33} ->
        peer_id = PeerId.from_secp256k1_pubkey_compressed(pub33)
        PeerId.to_base58(peer_id)

      pub when is_binary(pub) ->
        peer_id = PeerId.from_secp256k1_pubkey_compressed(pub)
        PeerId.to_base58(peer_id)

      other ->
        raise ArgumentError, "unsupported remote identity key #{inspect(other)}"
    end
  end

  defp cleanup_and_stop(data, reason) do
    Enum.each(data.yamux_stream_owners, fn {id, owner} ->
      send(owner, {:libp2p, :stream_closed, self(), id})
    end)

    {:stop, reason}
  end
end
