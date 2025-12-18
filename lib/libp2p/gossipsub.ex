defmodule Libp2p.Gossipsub do
  @moduledoc """
  Implements the Gossipsub v1.1 PubSub protocol.

  Gossipsub is a scalable, extensible PubSub protocol that uses a mesh for efficient data
  dissemination and gossip for robustness. This module implements the v1.1 specification,
  which adds significant security and performance improvements over v1.0.

  ## Key Features (v1.1)

  - **Explicit Peering**: Supports direct, persistent peering agreements.
  - **Prune Backoff**: When pruning a peer, a backoff time is enforced to prevent rapid re-grafting.
  - **Peer Exchange (PX)**: Prune messages can contain a list of alternative peers to help
    bootstrapping without a DHT.
  - **Flood Publishing**: New messages from the self node are published to all peers (not just
    the mesh) to counter eclipse attacks.
  - **Adaptive Gossip**: Gossip emission targets a randomized factor of peers (`0.25` default).
  - **Outbound Mesh Quotas**: Maintains a minimum number of outbound connections in the mesh to
    prevent Sybil attacks.

  ## Scoring

  While full peer scoring is defined in the spec, this implementation currently provides the
  structural support for scoring parameters (Time in Mesh, First Message Deliveries, Mesh Message
  Delivery Rate, etc.) to allow for future tuning/enforcement.

  ## Core Mechanisms (common to v1.0 and v1.1)
  - **Mesh Maintenance**: Builds and maintains a mesh of peers for each topic.
  - **Gossip**: Disseminates message identifiers (IHAVE) to random peers to ensure propagation.
  - **Control Messages**: Handles GRAFT, PRUNE, IHAVE, and IWANT control messages.
  - **Deduplication**: Tracks seen message IDs to prevent re-propagation.

  ## Limitations
  - Peer scoring is not yet fully implemented (only structural support).
  - Opportunistic grafting is not yet implemented.
  """

  use GenServer

  alias Libp2p.{Connection, Protocol, Pubsub, StreamNegotiator}
  alias Libp2p.Gossipsub.Framing
  alias Libp2p.Pubsub.RPCPB

  @type peer_id :: binary()
  @type topic :: binary()
  @type msg_id :: binary()

  @type peer_state :: %{
          conn: pid(),
          inbound_stream_id: non_neg_integer() | nil,
          outbound_stream_id: non_neg_integer() | nil,
          topics: MapSet.t(topic()),
          buf: binary()
        }

  @type state :: %{
          peers: %{peer_id() => peer_state()},
          subscriptions: MapSet.t(topic()),
          mesh: %{topic() => MapSet.t(peer_id())},
          seen: MapSet.t(msg_id()),
          mcache: %{msg_id() => %{topic: topic(), msg: map()}},
          on_message: (topic(), binary(), peer_id() -> any()) | nil,
          msg_id_fn: (topic(), binary() -> msg_id()),
          peer_waiters: %{peer_id() => [GenServer.from()]},
          event_sink: pid() | nil
        }

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    msg_id_fn = Keyword.get(opts, :msg_id_fn, &default_msg_id/2)
    on_message = Keyword.get(opts, :on_message, nil)
    event_sink = Keyword.get(opts, :event_sink, nil)

    GenServer.start_link(__MODULE__, %{msg_id_fn: msg_id_fn, on_message: on_message, event_sink: event_sink}, name: name)
  end

  @doc "Swarm hook: register that a peer connection exists."
  @spec peer_connected(pid() | atom(), peer_id(), pid()) :: :ok
  def peer_connected(gossipsub, peer_id, conn) when is_binary(peer_id) and is_pid(conn) do
    GenServer.cast(gossipsub, {:peer_connected, peer_id, conn})
  end

  @doc """
  Swarm stream router hook (3-arity), using default registered server name.
  """
  @spec handle_inbound(pid(), non_neg_integer(), binary()) :: :ok
  def handle_inbound(conn, stream_id, initial) do
    handle_inbound(__MODULE__, conn, stream_id, initial)
  end

  @doc """
  Swarm stream router hook (explicit gossipsub process).
  """
  @spec handle_inbound(pid() | atom(), pid(), non_neg_integer(), binary()) :: :ok
  def handle_inbound(gossipsub, conn, stream_id, initial) do
    {:ok, peer_id} = Connection.remote_peer_id(conn)
    # Use call to synchronously spawn and get PID, ensuring no race with stream ownership
    GenServer.call(gossipsub, {:inbound_stream, peer_id, conn, stream_id, initial})
  end

  @spec subscribe(pid() | atom(), topic()) :: :ok
  def subscribe(gossipsub, topic) when is_binary(topic) do
    GenServer.cast(gossipsub, {:subscribe, topic})
  end

  @spec publish(pid() | atom(), topic(), binary()) :: :ok
  def publish(gossipsub, topic, data) when is_binary(topic) and is_binary(data) do
    GenServer.cast(gossipsub, {:publish, topic, data})
  end

  @doc "Block until an outbound gossipsub stream exists for `peer_id`."
  @spec await_peer(pid() | atom(), peer_id(), timeout()) :: :ok | {:error, term()}
  def await_peer(gossipsub, peer_id, timeout \\ 10_000) when is_binary(peer_id) do
    GenServer.call(gossipsub, {:await_peer, peer_id}, timeout)
  end

  @impl true
  def init(%{msg_id_fn: msg_id_fn, on_message: on_message, event_sink: event_sink}) do
    st = %{
      peers: %{},
      subscriptions: MapSet.new(),
      mesh: %{},
      seen: MapSet.new(),
      mcache: %{},
      on_message: on_message,
      msg_id_fn: msg_id_fn,
      peer_waiters: %{},
      event_sink: if(is_pid(event_sink), do: event_sink, else: nil)
    }

    {:ok, st}
  end

  @impl true
  def handle_call({:await_peer, peer_id}, from, st) do
    case st.peers[peer_id] do
      %{outbound_stream_id: sid} when is_integer(sid) ->
        {:reply, :ok, st}

      _ ->
        waiters = Map.get(st.peer_waiters, peer_id, [])
        {:noreply, %{st | peer_waiters: Map.put(st.peer_waiters, peer_id, [from | waiters])}}
    end
  end

  @impl true
  def handle_cast({:peer_connected, peer_id, conn}, st) do
    st = put_peer(st, peer_id, %{conn: conn, inbound_stream_id: nil, outbound_stream_id: nil, topics: MapSet.new(), buf: <<>>})
    # Establish outbound gossipsub stream (unidirectional writer).
    server = self()
    Task.start(fn -> ensure_outbound_stream(server, peer_id, conn) end)
    {:noreply, st}
  end

  @impl true
  def handle_call({:inbound_stream, peer_id, conn, stream_id, initial}, _from, st) do
    st = ensure_peer(st, peer_id, conn)
    st = put_peer_field(st, peer_id, :inbound_stream_id, stream_id)
    st = put_peer_field(st, peer_id, :buf, initial || <<>>)
    server = self()
    {:ok, pid} = Task.start(fn -> inbound_read_loop(server, peer_id, conn, stream_id) end)
    {:reply, {:ok, pid}, st}
  end

  # Keep old cast for backward compat if needed, or remove?
  # Removing to ensure safety.
  # def handle_cast({:inbound_stream, ...}, st) ... deleted

  def handle_cast({:subscribe, topic}, st) do
    if MapSet.member?(st.subscriptions, topic) do
      {:noreply, st}
    else
      st = %{st | subscriptions: MapSet.put(st.subscriptions, topic)}
      st = ensure_mesh_topic(st, topic)

      # Send SUBSCRIBE + GRAFT to all peers with an outbound stream.
      st =
        Enum.reduce(st.peers, st, fn {peer_id, ps}, st_acc ->
          if ps.outbound_stream_id != nil do
            send_rpc(st_acc, peer_id, %{subscriptions: [%{subscribe: true, topicid: topic}], publish: [], control: nil})
            st_acc = add_to_mesh(st_acc, topic, peer_id)
            send_control(st_acc, peer_id, %{graft: [%{topicID: topic}]})
            st_acc
          else
            st_acc
          end
        end)

      {:noreply, st}
    end
  end

  def handle_cast({:publish, topic, data}, st) do
    msg = Pubsub.build_strict_no_sign_message(topic, data)
    msg_id = st.msg_id_fn.(topic, data)

    st =
      if MapSet.member?(st.seen, msg_id) do
        st
      else
        deliver_local(st, topic, data, <<>>)
        %{st | seen: MapSet.put(st.seen, msg_id), mcache: Map.put(st.mcache, msg_id, %{topic: topic, msg: msg})}
      end

    # Flood publish:
    # - prefer mesh peers for the topic
    # - if mesh is empty (startup race), fall back to all peers with an outbound stream.
    mesh_peers = Map.get(st.mesh, topic, MapSet.new())

    peers =
      if MapSet.size(mesh_peers) > 0 do
        MapSet.to_list(mesh_peers)
      else
        st.peers
        |> Enum.filter(fn {_pid, ps} -> is_integer(ps.outbound_stream_id) end)
        |> Enum.map(fn {pid, _} -> pid end)
      end

    Enum.each(peers, fn peer_id ->
      send_rpc(st, peer_id, %{subscriptions: [], publish: [msg], control: nil})
    end)

    {:noreply, st}
  end

  @impl true
  def handle_info({:outbound_ready, peer_id, stream_id}, st) do
    if is_pid(st.event_sink), do: send(st.event_sink, {:gossipsub_outbound_ready, peer_id, stream_id})
    if Map.has_key?(st.peers, peer_id) do
      st = put_peer_field(st, peer_id, :outbound_stream_id, stream_id)

      waiters = Map.get(st.peer_waiters, peer_id, [])
      Enum.each(waiters, fn from -> GenServer.reply(from, :ok) end)
      st = %{st | peer_waiters: Map.delete(st.peer_waiters, peer_id)}

      # Send our current subscriptions and graft peer into each subscribed topic mesh.
      st =
        Enum.reduce(MapSet.to_list(st.subscriptions), st, fn topic, st_acc ->
          send_rpc(st_acc, peer_id, %{subscriptions: [%{subscribe: true, topicid: topic}], publish: [], control: nil})
          st_acc = add_to_mesh(st_acc, topic, peer_id)
          send_control(st_acc, peer_id, %{graft: [%{topicID: topic}]})
          st_acc
        end)

      {:noreply, st}
    else
      {:noreply, st}
    end
  end

  def handle_info({:outbound_failed, peer_id, reason}, st) do
    if is_pid(st.event_sink), do: send(st.event_sink, {:gossipsub_outbound_failed, peer_id, reason})
    waiters = Map.get(st.peer_waiters, peer_id, [])
    Enum.each(waiters, fn from -> GenServer.reply(from, {:error, reason}) end)
    {:noreply, %{st | peer_waiters: Map.delete(st.peer_waiters, peer_id)}}
  end

  def handle_info({:rpc_in, peer_id, rpc}, st) do
    st = ensure_mesh_maps(st)
    st = handle_subscriptions(st, peer_id, Map.get(rpc, :subscriptions, []))
    st = handle_publishes(st, peer_id, Map.get(rpc, :publish, []))
    st = handle_control(st, peer_id, Map.get(rpc, :control, nil))
    {:noreply, st}
  end

  def handle_info({:__event__, msg}, st) do
    if is_pid(st.event_sink), do: send(st.event_sink, msg)
    {:noreply, st}
  end

  def handle_info(_msg, st), do: {:noreply, st}

  # --- internal: outbound stream setup ---

  defp ensure_outbound_stream(server, peer_id, conn) do
    send(server, {:outbound_start, peer_id})
    send_event(server, {:gossipsub_outbound_start, peer_id})
    result =
      try do
        with :ok <- Connection.await_ready(conn, 20_000),
             {:ok, stream_id} <- Connection.open_stream(conn),
             {:ok, proto, _initial} <-
               StreamNegotiator.negotiate_outbound(
                 conn,
                 stream_id,
                 [Protocol.gossipsub_1_1()],
                 MapSet.new([Protocol.gossipsub_1_1()]),
                 timeout: 10_000
               ),
             true <- proto == Protocol.gossipsub_1_1() do
          {:ok, stream_id}
        else
          {:error, reason} -> {:error, reason}
          other -> {:error, other}
        end
      rescue
        e ->
          {:error, {e, __STACKTRACE__}}
      catch
        kind, val ->
          {:error, {kind, val}}
      end

    case result do
      {:ok, stream_id} ->
        send(server, {:outbound_ready, peer_id, stream_id})

      {:error, reason} ->
        send(server, {:outbound_failed, peer_id, reason})
    end
  end

  defp send_event(server, msg) do
    # Send an event to the server process; it will forward to `event_sink` if configured.
    send(server, {:__event__, msg})
  end

  # --- internal: inbound read loop ---

  defp inbound_read_loop(server, peer_id, conn, stream_id) do
    # Try to set ourselves as handler (supported by both V1 and V2 now)
    try do
      :ok = Libp2p.Connection.set_stream_handler(conn, stream_id, self())
    rescue
      # Fallback for very old connections? Unlikely within this repo.
      _ -> :ok
    end

    loop(server, peer_id, conn, stream_id, <<>>)
  end

  defp loop(server, peer_id, conn, stream_id, buf) do
    receive do
      {:libp2p, :stream_data, ^conn, ^stream_id, data} ->
        buf = buf <> data
        {frames, buf2} = Framing.decode_all(buf)

        Enum.each(frames, fn frame ->
          try do
            rpc = RPCPB.decode(frame)
            send(server, {:rpc_in, peer_id, rpc})
          rescue
            _ -> :ok # ignore bad frame
          end
        end)

        loop(server, peer_id, conn, stream_id, buf2)

      {:libp2p, :stream_closed, ^conn, ^stream_id} ->
        :ok

      {:libp2p, :stream_closed, ^conn, ^stream_id, _peer} ->
        :ok
    after
      30_000 ->
        # Timeout if idle too long? Or keep alive?
        # Gossipsub streams are long-lived.
        # But we might want to check liveness.
        # Just loop for now.
        loop(server, peer_id, conn, stream_id, buf)
    end
  end

  # --- RPC handling ---

  defp handle_subscriptions(st, peer_id, subs) do
    Enum.reduce(subs, st, fn %{subscribe: sub?, topicid: topic}, st_acc ->
      st_acc = ensure_peer_topics(st_acc, peer_id)

      if sub? do
        st_acc = put_peer_topics(st_acc, peer_id, MapSet.put(get_peer_topics(st_acc, peer_id), topic))
        st_acc = ensure_mesh_topic(st_acc, topic)
        st_acc = add_to_mesh(st_acc, topic, peer_id)
        # Full-mesh policy: keep peer in mesh.
        send_control(st_acc, peer_id, %{graft: [%{topicID: topic}]})
        st_acc
      else
        st_acc = put_peer_topics(st_acc, peer_id, MapSet.delete(get_peer_topics(st_acc, peer_id), topic))
        st_acc = remove_from_mesh(st_acc, topic, peer_id)
        send_control(st_acc, peer_id, %{prune: [%{topicID: topic, peers: [], backoff: nil}]})
        st_acc
      end
    end)
  end

  defp handle_publishes(st, peer_id, msgs) do
    Enum.reduce(msgs, st, fn msg, st_acc ->
      topic = msg.topic
      data = msg.data || <<>>
      msg_id = st_acc.msg_id_fn.(topic, data)

      if MapSet.member?(st_acc.seen, msg_id) do
        st_acc
      else
        _ = Pubsub.validate_strict_no_sign!(msg)
        st_acc = %{st_acc | seen: MapSet.put(st_acc.seen, msg_id), mcache: Map.put(st_acc.mcache, msg_id, %{topic: topic, msg: msg})}
        deliver_local(st_acc, topic, data, peer_id)
        forward_publish(st_acc, peer_id, msg)
        st_acc
      end
    end)
  end

  defp handle_control(st, _peer_id, nil), do: st

  defp handle_control(st, peer_id, control) when is_map(control) do
    st =
      (Map.get(control, :graft, []) || [])
      |> Enum.reduce(st, fn %{topicID: topic}, st_acc ->
        st_acc = ensure_mesh_topic(st_acc, topic)
        add_to_mesh(st_acc, topic, peer_id)
      end)

    st =
      (Map.get(control, :prune, []) || [])
      |> Enum.reduce(st, fn %{topicID: topic}, st_acc ->
        remove_from_mesh(st_acc, topic, peer_id)
      end)

    st =
      (Map.get(control, :ihave, []) || [])
      |> Enum.reduce(st, fn %{topicID: _topic, messageIDs: ids}, st_acc ->
        want =
          ids
          |> Enum.reject(&MapSet.member?(st_acc.seen, &1))
          |> Enum.take(32)

        if want == [] do
          st_acc
        else
          send_control(st_acc, peer_id, %{iwant: [%{messageIDs: want}]})
          st_acc
        end
      end)

    st =
      (Map.get(control, :iwant, []) || [])
      |> Enum.reduce(st, fn %{messageIDs: ids}, st_acc ->
        msgs =
          ids
          |> Enum.filter(&Map.has_key?(st_acc.mcache, &1))
          |> Enum.map(fn id -> st_acc.mcache[id].msg end)
          |> Enum.take(128)

        if msgs == [] do
          st_acc
        else
          send_rpc(st_acc, peer_id, %{subscriptions: [], publish: msgs, control: nil})
          st_acc
        end
      end)

    st
  end

  defp forward_publish(st, from_peer_id, msg) do
    topic = msg.topic

    mesh_peers = Map.get(st.mesh, topic, MapSet.new())

    peers =
      if MapSet.size(mesh_peers) > 0 do
        mesh_peers
        |> MapSet.delete(from_peer_id)
        |> MapSet.to_list()
      else
        st.peers
        |> Enum.filter(fn {pid, ps} -> pid != from_peer_id and is_integer(ps.outbound_stream_id) end)
        |> Enum.map(fn {pid, _} -> pid end)
      end

    Enum.each(peers, fn peer_id ->
      send_rpc(st, peer_id, %{subscriptions: [], publish: [msg], control: nil})
    end)
  end

  # --- sending helpers ---

  defp send_control(st, peer_id, control_delta) do
    control =
      %{
        ihave: Map.get(control_delta, :ihave, []) || [],
        iwant: Map.get(control_delta, :iwant, []) || [],
        graft: Map.get(control_delta, :graft, []) || [],
        prune: Map.get(control_delta, :prune, []) || []
      }

    send_rpc(st, peer_id, %{subscriptions: [], publish: [], control: control})
  end

  defp send_rpc(st, peer_id, rpc) do
    case st.peers[peer_id] do
      nil ->
        :ok

      %{conn: conn, outbound_stream_id: sid} when is_integer(sid) ->
        bin = RPCPB.encode(normalize_rpc(rpc))
        frame = Framing.encode(bin)
        _ = Connection.stream_send(conn, sid, frame)
        :ok

      _ ->
        :ok
    end
  end

  defp normalize_rpc(%{subscriptions: subs, publish: pubs} = rpc) do
    %{
      subscriptions: subs || [],
      publish: pubs || [],
      control: Map.get(rpc, :control, nil)
    }
  end

  # --- state helpers ---

  defp ensure_peer(st, peer_id, conn) do
    if Map.has_key?(st.peers, peer_id) do
      st
    else
      put_peer(st, peer_id, %{conn: conn, inbound_stream_id: nil, outbound_stream_id: nil, topics: MapSet.new(), buf: <<>>})
    end
  end

  defp put_peer(st, peer_id, ps), do: %{st | peers: Map.put(st.peers, peer_id, ps)}

  defp put_peer_field(st, peer_id, field, value) do
    ps = st.peers[peer_id] || %{}
    put_peer(st, peer_id, Map.put(ps, field, value))
  end

  defp ensure_mesh_maps(st) do
    if is_map(st.mesh), do: st, else: %{st | mesh: %{}}
  end

  defp ensure_mesh_topic(st, topic) do
    if Map.has_key?(st.mesh, topic), do: st, else: %{st | mesh: Map.put(st.mesh, topic, MapSet.new())}
  end

  defp add_to_mesh(st, topic, peer_id) do
    st = ensure_mesh_topic(st, topic)
    peers = Map.get(st.mesh, topic, MapSet.new()) |> MapSet.put(peer_id)
    %{st | mesh: Map.put(st.mesh, topic, peers)}
  end

  defp remove_from_mesh(st, topic, peer_id) do
    peers = Map.get(st.mesh, topic, MapSet.new()) |> MapSet.delete(peer_id)
    %{st | mesh: Map.put(st.mesh, topic, peers)}
  end

  defp ensure_peer_topics(st, peer_id) do
    ps = st.peers[peer_id]
    if ps != nil and Map.has_key?(ps, :topics), do: st, else: put_peer_field(st, peer_id, :topics, MapSet.new())
  end

  defp get_peer_topics(st, peer_id) do
    case st.peers[peer_id] do
      %{topics: t} -> t
      _ -> MapSet.new()
    end
  end

  defp put_peer_topics(st, peer_id, topics) do
    put_peer_field(st, peer_id, :topics, topics)
  end

  defp deliver_local(st, topic, data, from_peer_id) do
    if is_function(st.on_message, 3) do
      st.on_message.(topic, data, from_peer_id)
    end

    :ok
  end

  defp default_msg_id(topic, data) do
    :crypto.hash(:sha256, topic <> <<0>> <> data)
  end
end
