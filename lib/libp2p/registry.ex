defmodule Libp2p.Registry do
  @moduledoc """
  Global registry for libp2p connection processes, indexed by PeerID.
  """

  use GenServer

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @spec register(binary(), pid(), atom() | pid()) :: :ok
  def register(peer_id, pid, name \\ __MODULE__) when is_binary(peer_id) and is_pid(pid) do
    GenServer.cast(name, {:register, peer_id, pid})
  end

  @spec unregister(binary(), atom() | pid()) :: :ok
  def unregister(peer_id, name \\ __MODULE__) when is_binary(peer_id) do
    GenServer.cast(name, {:unregister, peer_id})
  end

  @spec get(binary(), atom() | pid()) :: nil | pid()
  def get(peer_id, name \\ __MODULE__) when is_binary(peer_id), do: GenServer.call(name, {:get, peer_id})

  @spec list(atom() | pid()) :: [{binary(), pid()}]
  def list(name \\ __MODULE__), do: GenServer.call(name, :list)

  @impl true
  def init(_opts), do: {:ok, %{conns: %{}}}

  @impl true
  def handle_call({:get, peer_id}, _from, st) do
    pid = Map.get(st.conns, peer_id)
    pid = if is_pid(pid) and Process.alive?(pid), do: pid, else: nil
    {:reply, pid, st}
  end

  def handle_call(:list, _from, st) do
    out =
      st.conns
      |> Enum.filter(fn {_k, pid} -> is_pid(pid) and Process.alive?(pid) end)

    {:reply, out, st}
  end

  @impl true
  def handle_cast({:register, peer_id, pid}, st) do
    Process.monitor(pid)
    {:noreply, %{st | conns: Map.put(st.conns, peer_id, pid)}}
  end

  def handle_cast({:unregister, peer_id}, st) do
    {:noreply, %{st | conns: Map.delete(st.conns, peer_id)}}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, _reason}, st) do
    conns =
      st.conns
      |> Enum.reject(fn {_peer_id, p} -> p == pid end)
      |> Map.new()

    {:noreply, %{st | conns: conns}}
  end
end
