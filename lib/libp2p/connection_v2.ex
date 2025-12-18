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

  use GenServer

  require Logger

  alias Libp2p.{Identity, MultistreamSelect, Noise, PeerId, Registry}
  alias Libp2p.Yamux.Session, as: Yamux

  @sec_proposals ["/noise"]
  @sec_supported MapSet.new(["/noise"])
  @mux_proposals ["/yamux/1.0.0"]
  @mux_supported MapSet.new(["/yamux/1.0.0"])

  @type role :: :initiator | :responder

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @spec remote_peer_id(pid()) :: {:ok, binary()} | {:error, term()}
  def remote_peer_id(conn), do: GenServer.call(conn, :remote_peer_id)

  @spec await_ready(pid(), timeout()) :: :ok | {:error, term()}
  def await_ready(conn, timeout \\ 20_000) do
    GenServer.call(conn, :await_ready, timeout)
  end

  @spec open_stream(pid()) :: {:ok, non_neg_integer()} | {:error, term()}
  def open_stream(conn) when is_pid(conn), do: GenServer.call(conn, :open_stream, 30_000)

  @spec open_stream(pid(), binary()) :: {:ok, non_neg_integer()} | {:error, term()}
  def open_stream(conn, initial_data) when is_pid(conn) and is_binary(initial_data),
    do: GenServer.call(conn, {:open_stream, initial_data}, 30_000)

  @spec send_stream(pid(), non_neg_integer(), binary()) :: :ok | {:error, term()}
  def send_stream(conn, stream_id, data) when is_pid(conn) and is_integer(stream_id) and is_binary(data),
    do: GenServer.call(conn, {:send_stream, stream_id, data})

  @spec close_stream(pid(), non_neg_integer()) :: :ok | {:error, term()}
  def close_stream(conn, stream_id) when is_pid(conn) and is_integer(stream_id),
    do: GenServer.call(conn, {:close_stream, stream_id})

  @spec peer_store(pid()) :: pid() | atom()
  def peer_store(conn), do: GenServer.call(conn, :peer_store)

  @doc "Reset (RST) a yamux stream."
  @spec reset_stream(pid() | atom(), non_neg_integer()) :: :ok | {:error, term()}
  def reset_stream(conn, stream_id) do
    GenServer.call(conn, {:reset_stream, stream_id})
  end

  @doc "Set the process that will receive stream events."
  @spec set_stream_handler(pid(), non_neg_integer(), pid()) :: :ok
  def set_stream_handler(conn, stream_id, pid) do
    GenServer.call(conn, {:set_stream_handler, stream_id, pid})
  end

  @impl true
  def init(opts) do
    role = Keyword.fetch!(opts, :role)
    %Identity{} = identity = Keyword.fetch!(opts, :identity)
    handler = Keyword.get(opts, :handler, nil)
    notify_conn_ready? = Keyword.get(opts, :notify_conn_ready?, false)
    expected_peer_id = Keyword.get(opts, :expected_peer_id, nil)
    enforce_expected_peer_id? = Keyword.get(opts, :enforce_expected_peer_id?, true)
    peer_store = Keyword.get(opts, :peer_store, Libp2p.PeerStore)

    dial_timeout_ms =
      Keyword.get(
        opts,
        :dial_timeout_ms,
        3_000
      )

    noise_prologue = Keyword.get(opts, :noise_prologue, <<>>)
    noise_hash_protocol_name? = Keyword.get(opts, :noise_hash_protocol_name?, false)
    noise_hkdf_swap? = Keyword.get(opts, :noise_hkdf_swap?, false)
    noise_nonce_be? = Keyword.get(opts, :noise_nonce_be?, false)

    {socket_info, initial_state_update, socket_opts} =
      case role do
        :initiator ->
          {ip, port} = Keyword.fetch!(opts, :dial)
          GenServer.cast(self(), :connect)
          {{:outbound, nil, {ip, port}}, %{phase: :connecting}, []}

        :responder ->
          sock = Keyword.fetch!(opts, :socket)
          {:ok, {ip, port}} = :inet.peername(sock)
          {{:inbound, sock, {ip, port}}, %{phase: :mss_security}, [active: :once]}
      end

    {_dir, sock, peer_addr} = socket_info
    if is_port(sock), do: :ok = :inet.setopts(sock, socket_opts)

    Logger.debug(%{
      event: "p2p_conn_init",
      role: role,
      peer_addr: inspect(peer_addr),
      expected_peer_id: expected_peer_id,
      noise: %{
        prologue_len: byte_size(noise_prologue),
        hash_protocol_name?: noise_hash_protocol_name?,
        hkdf_swap?: noise_hkdf_swap?,
        nonce_be?: noise_nonce_be?
      }
    })

    # security multistream-select (plaintext)
    mss =
      case role do
        :initiator -> MultistreamSelect.new_initiator(@sec_proposals)
        :responder -> MultistreamSelect.new_responder()
      end

    {out0, mss} =
      if role == :responder do
        MultistreamSelect.start(mss)
      else
        {<<>>, mss}
      end

    if out0 != <<>> and is_port(sock), do: :ok = :gen_tcp.send(sock, out0)

    noise =
      Noise.new(
        if(role == :initiator, do: :initiator, else: :responder),
        identity,
        noise_prologue,
        noise_hash_protocol_name?,
        noise_hkdf_swap?,
        noise_nonce_be?
      )

    st = %{
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
      # plaintext MSS + noise handshake buffers
      mss_state: mss,
      phase: initial_state_update.phase,
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
      # muxer MSS over noise
      mux_mss_state: nil,
      # yamux
      yamux: nil,
      yamux_stream_owners: %{},
      ready_waiters: []
    }

    {:ok, st}
  end

  @impl true
  def handle_cast(
        :connect,
        %{role: :initiator, peer_addr: {ip, port}, dial_timeout_ms: timeout} = st
      ) do
    case :gen_tcp.connect(ip, port, [:binary, active: :once, packet: 0, nodelay: true, keepalive: true], timeout) do
      {:ok, sock} ->
        {out, mss} = MultistreamSelect.start(st.mss_state)
        if out != <<>>, do: :ok = :gen_tcp.send(sock, out)

        st = %{st | sock: sock, phase: :mss_security, mss_state: mss}
        :ok = :inet.setopts(sock, active: :once)
        st = drive(st)
        {:noreply, st}

      {:error, reason} ->
        {:stop, {:shutdown, {:dial_failed, {ip, port}, reason}}, st}
    end
  end

  @impl true
  def handle_call(:await_ready, _from, %{phase: :yamux} = st) do
    {:reply, :ok, st}
  end

  def handle_call(:await_ready, from, st) do
    {:noreply, %{st | ready_waiters: [from | st.ready_waiters]}}
  end

  def handle_call(:remote_peer_id, _from, st), do: {:reply, {:ok, st.remote_peer_id}, st}

# ...

  defp notify_waiters(st) do
    Enum.each(st.ready_waiters, fn from -> GenServer.reply(from, :ok) end)
    %{st | ready_waiters: []}
  end

# ... (in finish_noise and handle_transport_plaintext)


  def handle_call(:peer_store, _from, st), do: {:reply, st.peer_store, st}



  def handle_call(:open_stream, {from_pid, _} = _from, %{phase: :yamux} = st) do
    {id, out, y2} = Yamux.open_stream(st.yamux)
    st = %{st | yamux: y2, yamux_stream_owners: Map.put(st.yamux_stream_owners, id, from_pid)}
    st = send_transport(st, out)
    {:reply, {:ok, id}, st}
  end

  def handle_call({:open_stream, initial_data}, {from_pid, _} = _from, %{phase: :yamux} = st)
      when is_binary(initial_data) do
    {id, out, y2} = Yamux.open_stream_with_data(st.yamux, initial_data)
    st = %{st | yamux: y2, yamux_stream_owners: Map.put(st.yamux_stream_owners, id, from_pid)}
    st = send_transport(st, out)
    {:reply, {:ok, id}, st}
  end

  def handle_call(:open_stream, _from, st), do: {:reply, {:error, :not_ready}, st}

  def handle_call({:open_stream, _initial_data}, _from, st),
    do: {:reply, {:error, :not_ready}, st}

  def handle_call({:send_stream, stream_id, data}, _from, %{phase: :yamux} = st) do
    {out, y2} = Yamux.send_data(st.yamux, stream_id, data)
    st = %{st | yamux: y2}
    st = send_transport(st, out)
    {:reply, :ok, st}
  rescue
    e ->
      Logger.error("ConnectionV2.send_stream failed: #{inspect(e)}")
      {:reply, {:error, :bad_stream}, st}
  end

  def handle_call({:send_stream, _stream_id, _data}, _from, st),
    do: {:reply, {:error, :not_ready}, st}

  def handle_call({:close_stream, stream_id}, _from, %{phase: :yamux} = st) do
    {out, y2} = Yamux.close_stream(st.yamux, stream_id)
    st = %{st | yamux: y2, yamux_stream_owners: Map.delete(st.yamux_stream_owners, stream_id)}
    st = send_transport(st, out)
    {:reply, :ok, st}
  rescue
    _ -> {:reply, {:error, :bad_stream}, st}
  end

  def handle_call({:close_stream, _stream_id}, _from, st), do: {:reply, {:error, :not_ready}, st}

  def handle_call({:reset_stream, stream_id}, _from, %{phase: :yamux} = st) do
    {out, y2} = Yamux.reset_stream(st.yamux, stream_id)
    st = %{st | yamux: y2, yamux_stream_owners: Map.delete(st.yamux_stream_owners, stream_id)}
    st = send_transport(st, out)
    {:reply, :ok, st}
  rescue
    _ -> {:reply, {:error, :bad_stream}, st}
  end

  def handle_call({:reset_stream, _stream_id}, _from, st), do: {:reply, {:error, :not_ready}, st}

  # V1 Compatibility Aliases
  def handle_call({:stream_send, id, data}, from, st), do: handle_call({:send_stream, id, data}, from, st)
  def handle_call({:stream_close, id}, from, st), do: handle_call({:close_stream, id}, from, st)

  def handle_call({:set_stream_handler, stream_id, pid}, _from, %{phase: :yamux} = st) do
    # If there is buffered data, we should probably forward it?
    # But current implementation pushes data immediately.
    # If handler was Swarm, Swarm dropped it.
    # So we can only switch ownership for future data.
    st = %{st | yamux_stream_owners: Map.put(st.yamux_stream_owners, stream_id, pid)}
    {:reply, :ok, st}
  end

  def handle_call({:set_stream_handler, _stream_id, _pid}, _from, st), do: {:reply, {:error, :not_ready}, st}

  @impl true
  def handle_info({:tcp, sock, data}, %{sock: sock} = st) do
    st = %{st | buf: st.buf <> data}
    st = drive(st)
    :ok = :inet.setopts(sock, active: :once)
    {:noreply, st}
  end

  def handle_info(:start_socket, st) do
    :ok = :inet.setopts(st.sock, active: :once)
    st = drive(st)
    {:noreply, st}
  end

  def handle_info({:tcp_closed, sock}, %{sock: sock} = st) do
    Logger.debug(%{
      event: "p2p_tcp_closed",
      phase: st.phase,
      peer_addr: inspect(st.peer_addr),
      role: st.role,
      remote_peer_id: st.remote_peer_id
    })

    # Best-effort: wake any tasks blocked waiting on stream events.
    Enum.each(st.yamux_stream_owners, fn {stream_id, owner} ->
      if is_pid(owner) do
        send(owner, {:libp2p, :stream_closed, self(), stream_id})
      end
    end)

    if is_binary(st.remote_peer_id), do: Registry.unregister(st.remote_peer_id)
    {:stop, :normal, st}
  end

  def handle_info({:tcp_error, sock, reason}, %{sock: sock} = st) do
    Logger.debug(%{
      event: "p2p_tcp_error",
      phase: st.phase,
      peer_addr: inspect(st.peer_addr),
      role: st.role,
      reason: inspect(reason)
    })

    Enum.each(st.yamux_stream_owners, fn {stream_id, owner} ->
      if is_pid(owner) do
        send(owner, {:libp2p, :stream_closed, self(), stream_id})
      end
    end)

    if is_binary(st.remote_peer_id), do: Registry.unregister(st.remote_peer_id)
    {:stop, :normal, st}
  end

  defp drive(%{phase: :mss_security} = st) do
    {events, out, mss2} = MultistreamSelect.feed(st.mss_state, st.buf, @sec_supported)
    if out != <<>>, do: _ = :gen_tcp.send(st.sock, out)
    st = %{st | mss_state: mss2, buf: mss2.buf}

    case Enum.find(events, fn e -> match?({:selected, _}, e) end) do
      {:selected, "/noise"} ->
        Logger.debug(%{
          event: "p2p_security_selected",
          peer_addr: inspect(st.peer_addr),
          role: st.role,
          selected: "/noise"
        })

        st = %{st | phase: :noise, noise_buf: st.buf, buf: <<>>}
        st = start_noise(st)
        drive_noise(st)

      _ ->
        st
    end
  end

  defp drive(%{phase: :noise} = st) do
    st = %{st | noise_buf: st.noise_buf <> st.buf, buf: <<>>}
    st = drive_noise(st)
    st
  end

  defp drive(%{phase: :mss_muxer} = st) do
    st = %{st | noise_buf: st.noise_buf <> st.buf, buf: <<>>}
    st = drive_noise_transport(st)
    st
  end

  defp drive(%{phase: :yamux} = st) do
    st = %{st | noise_buf: st.noise_buf <> st.buf, buf: <<>>}
    st = drive_noise_transport(st)
    st
  end

  defp start_noise(%{role: :initiator} = st) do
    {msg1, noise2} = Noise.initiator_msg1(st.noise)
    _ = :gen_tcp.send(st.sock, Noise.frame(msg1))
    %{st | noise: noise2, noise_stage: :wait_msg2}
  end

  defp start_noise(%{role: :responder} = st) do
    %{st | noise_stage: :wait_msg1}
  end

  defp drive_noise(%{noise_stage: :wait_msg1} = st) do
    case Noise.deframe(st.noise_buf) do
      :more ->
        st

      {msg1, rest} ->
        {msg2, noise2} = Noise.responder_msg2(st.noise, msg1)
        _ = :gen_tcp.send(st.sock, Noise.frame(msg2))
        %{st | noise: noise2, noise_buf: rest, noise_stage: :wait_msg3}
    end
  end

  defp drive_noise(%{noise_stage: :wait_msg2} = st) do
    case Noise.deframe(st.noise_buf) do
      :more ->
        st

      {msg2, rest} ->
        try do
          {msg3, noise2, {cs_out, cs_in}} = Noise.initiator_msg3(st.noise, msg2)
          _ = :gen_tcp.send(st.sock, Noise.frame(msg3))
          st = %{st | noise: noise2, noise_out: cs_out, noise_in: cs_in, noise_buf: rest}
          finish_noise(st)
        rescue
          e in ArgumentError ->
            exit({:shutdown, {:handshake_failed, Exception.message(e)}})
        end
    end
  end

  defp drive_noise(%{noise_stage: :wait_msg3} = st) do
    case Noise.deframe(st.noise_buf) do
      :more ->
        st

      {msg3, rest} ->
        try do
          {noise2, {cs_in, cs_out}} = Noise.responder_finish(st.noise, msg3)
          st = %{st | noise: noise2, noise_out: cs_out, noise_in: cs_in, noise_buf: rest}
          finish_noise(st)
        rescue
          e in ArgumentError ->
            exit({:shutdown, {:handshake_failed, Exception.message(e)}})
        end
    end
  end

  defp finish_noise(st) do
    remote_peer_id = derive_remote_peer_id!(st)

    Logger.debug(%{
      event: "p2p_noise_handshake_completed",
      peer_addr: inspect(st.peer_addr),
      role: st.role,
      remote_peer_id: remote_peer_id
    })

    if st.enforce_expected_peer_id? and is_binary(st.expected_peer_id) and
         st.expected_peer_id != remote_peer_id do
      _ = :gen_tcp.close(st.sock)
      exit({:shutdown, {:peer_id_mismatch, st.expected_peer_id, remote_peer_id}})
    end

    st = %{st | remote_peer_id: remote_peer_id}

    case Map.get(st.noise, :selected_stream_muxer, nil) do
      "/yamux/1.0.0" ->
        y = Yamux.new(if(st.role == :initiator, do: :client, else: :server))
        Registry.register(st.remote_peer_id, self())
        st = %{st | phase: :yamux, yamux: y, mux_mss_state: nil}

        if st.notify_conn_ready? and st.handler != nil do
          send(st.handler, {:libp2p, :conn_ready, self(), st.remote_peer_id})
        end

        if st.notify_ready != nil do
          send(st.notify_ready, {:libp2p, :conn_ready, self(), st.remote_peer_id})
        end

        st = notify_waiters(st)
        drive_noise_transport(st)

      nil ->
        mss =
          case st.role do
            :initiator -> MultistreamSelect.new_initiator(@mux_proposals)
            :responder -> MultistreamSelect.new_responder()
          end

        {out0, mss} = MultistreamSelect.start(mss)
        st = if out0 != <<>>, do: send_transport(st, out0), else: st
        st = %{st | mux_mss_state: mss, phase: :mss_muxer}
        drive_noise_transport(st)

      other ->
        Logger.warning("unsupported negotiated stream muxer #{inspect(other)}")
        st
    end
  end

  defp drive_noise_transport(st) do
    case Noise.deframe(st.noise_buf) do
      :more ->
        st

      {ct, rest} ->
        {pt, cs_in} = Noise.transport_decrypt(st.noise_in, ct, <<>>)
        st = %{st | noise_in: cs_in, noise_buf: rest}
        st = handle_transport_plaintext(st, pt)
        drive_noise_transport(st)
    end
  rescue
    _ -> st
  end

  defp handle_transport_plaintext(%{phase: :mss_muxer} = st, bytes) do
    {events, out, mss2} = MultistreamSelect.feed(st.mux_mss_state, bytes, @mux_supported)

    st = %{st | mux_mss_state: mss2}
    st = if out != <<>>, do: send_transport(st, out), else: st

    case Enum.find(events, fn e -> match?({:selected, _}, e) end) do
      {:selected, "/yamux/1.0.0"} ->
        y = Yamux.new(if(st.role == :initiator, do: :client, else: :server))
        leftover = Map.get(mss2, :buf, <<>>)

        y2 =
          if leftover != <<>> do
            {events2, out2, y2} = Yamux.feed(y, leftover)
            st2 = %{st | yamux: y2}
            st2 = if out2 != <<>>, do: send_transport(st2, out2), else: st2

            Enum.each(events2, fn
              {:stream_open, id} ->
                if st2.handler != nil,
                  do: send(st2.handler, {:libp2p, :stream_open, self(), id, st2.remote_peer_id})

              {:stream_data, id, data} ->
                case Map.get(st2.yamux_stream_owners, id) do
                  owner when is_pid(owner) ->
                    send(owner, {:libp2p, :stream_data, self(), id, data})

                  _ ->
                    if st2.handler != nil,
                      do: send(st2.handler, {:libp2p, :stream_data, self(), id, data, st2.remote_peer_id})
                end

              {:stream_close, id} ->
                if st2.handler != nil,
                  do: send(st2.handler, {:libp2p, :stream_closed, self(), id, st2.remote_peer_id})

              _ ->
                :ok
            end)

            st2.yamux
          else
            y
          end

        Registry.register(st.remote_peer_id, self())
        st2 = %{st | phase: :yamux, yamux: y2, mux_mss_state: nil}

        if st2.notify_conn_ready? and st2.handler != nil do
          send(st2.handler, {:libp2p, :conn_ready, self(), st2.remote_peer_id})
        end

        if st2.notify_ready != nil do
          send(st2.notify_ready, {:libp2p, :conn_ready, self(), st2.remote_peer_id})
        end

        st2 = notify_waiters(st2)
        st2

      _ ->
        st
    end
  end

  defp handle_transport_plaintext(%{phase: :yamux} = st, bytes) do
    {events, out, y2} = Yamux.feed(st.yamux, bytes)
    st = %{st | yamux: y2}
    st = if out != <<>>, do: send_transport(st, out), else: st

    Enum.reduce(events, st, fn
      {:stream_open, id}, acc ->
        if acc.handler != nil,
          do: send(acc.handler, {:libp2p, :stream_open, self(), id, acc.remote_peer_id})

        acc

      {:stream_data, id, data}, acc ->
        case Map.get(acc.yamux_stream_owners, id) do
          owner when is_pid(owner) ->
            Logger.debug("ConnectionV2 dispatching #{byte_size(data)} bytes to owner #{inspect(owner)}")
            send(owner, {:libp2p, :stream_data, self(), id, data})

          _ ->
            if acc.handler != nil do
              Logger.debug("ConnectionV2 dispatching #{byte_size(data)} bytes to handler #{inspect(acc.handler)}")
              send(acc.handler, {:libp2p, :stream_data, self(), id, data, acc.remote_peer_id})
            end
        end

        acc

      {:stream_close, id}, acc ->
        case Map.get(acc.yamux_stream_owners, id) do
          owner when is_pid(owner) ->
            send(owner, {:libp2p, :stream_closed, self(), id})

          _ ->
            if acc.handler != nil,
              do: send(acc.handler, {:libp2p, :stream_closed, self(), id, acc.remote_peer_id})
        end

        %{acc | yamux_stream_owners: Map.delete(acc.yamux_stream_owners, id)}

      {:stream_reset, id}, acc ->
        case Map.get(acc.yamux_stream_owners, id) do
          owner when is_pid(owner) ->
            send(owner, {:libp2p, :stream_closed, self(), id})

          _ ->
            :ok
        end

        %{acc | yamux_stream_owners: Map.delete(acc.yamux_stream_owners, id)}

      {:go_away, _code}, acc ->
        acc
    end)
  end

  defp send_transport(st, plaintext) when is_binary(plaintext) do
    {ct, cs_out} = Noise.transport_encrypt(st.noise_out, plaintext, <<>>)

    case :gen_tcp.send(st.sock, Noise.frame(ct)) do
      :ok ->
        %{st | noise_out: cs_out}

      {:error, _reason} ->
        st
    end
  end

  defp derive_remote_peer_id!(st) do
    case st.noise.remote_identity_key do
      {:secp256k1, pub33} ->
        peer_id = PeerId.from_secp256k1_pubkey_compressed(pub33)
        PeerId.to_base58(peer_id)

      # In some cases it might be a raw binary or a different tuple
      pub when is_binary(pub) ->
        peer_id = PeerId.from_secp256k1_pubkey_compressed(pub)
        PeerId.to_base58(peer_id)

      other ->
        Logger.error("unsupported remote identity key #{inspect(other)}")
        raise ArgumentError, "unsupported remote identity key"
    end
  end

  defp notify_waiters(st) do
    Enum.each(st.ready_waiters, fn from -> GenServer.reply(from, :ok) end)
    %{st | ready_waiters: []}
  end
end
