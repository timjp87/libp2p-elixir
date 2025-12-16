defmodule Libp2p.ReqRespServer do
  @moduledoc """
  Minimal concurrency gating for Req/Resp handlers.

  Ethereum's p2p-interface requires limiting concurrent requests per protocol ID.
  This module provides a reusable mechanism that libp2p stream handlers can call.
  """

  use GenServer

  @type key :: {binary(), binary()} | binary()

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @spec handle(pid() | atom(), key(), binary(), (binary() -> binary()), keyword()) ::
          {:ok, binary()} | {:error, term()}
  def handle(server, key, request_bytes, handler_fun, opts \\ [])
      when (is_pid(server) or is_atom(server)) and is_binary(request_bytes) and is_function(handler_fun, 1) do
    timeout = Keyword.get(opts, :timeout, 5_000)
    max = Keyword.get(opts, :max_concurrent, 2)
    GenServer.call(server, {:handle, key, request_bytes, handler_fun, timeout, max}, timeout + 1_000)
  end

  @impl true
  def init(_opts), do: {:ok, %{inflight: %{}, pending: %{}}}

  @impl true
  def handle_call({:handle, key, req, fun, timeout, max}, from, st) do
    in_flight = Map.get(st.inflight, key, 0)

    if in_flight >= max do
      {:reply, {:error, :max_concurrent_requests}, st}
    else
      st = put_inflight(st, key, in_flight + 1)

      ref = make_ref()
      timer_ref = Process.send_after(self(), {:timeout, ref}, timeout)

      st = %{st | pending: Map.put(st.pending, ref, %{key: key, from: from, timer: timer_ref})}

      # run handler outside the GenServer
      server_pid = self()
      _pid =
        spawn(fn ->
          result =
            try do
              {:ok, fun.(req)}
            catch
              :exit, reason -> {:error, {:exit, reason}}
              kind, reason -> {:error, {kind, reason}}
            end

          send(server_pid, {:done, ref, result})
        end)

      {:noreply, st}
    end
  end

  @impl true
  def handle_info({:done, ref, result}, st) do
    case Map.pop(st.pending, ref) do
      {nil, _pending} ->
        # already timed out
        {:noreply, st}

      {%{key: key, from: from, timer: timer_ref}, pending2} ->
        _ = Process.cancel_timer(timer_ref)
        st = %{st | pending: pending2}
        st = put_inflight(st, key, Map.get(st.inflight, key, 1) - 1)
        GenServer.reply(from, result)
        {:noreply, st}
    end
  end

  def handle_info({:timeout, ref}, st) do
    case Map.pop(st.pending, ref) do
      {nil, _pending} ->
        {:noreply, st}

      {%{key: key, from: from, timer: _timer_ref}, pending2} ->
        st = %{st | pending: pending2}
        st = put_inflight(st, key, Map.get(st.inflight, key, 1) - 1)
        GenServer.reply(from, {:error, :timeout})
        {:noreply, st}
    end
  end

  defp put_inflight(st, key, n) when n <= 0 do
    %{st | inflight: Map.delete(st.inflight, key)}
  end

  defp put_inflight(st, key, n) do
    %{st | inflight: Map.put(st.inflight, key, n)}
  end

end
