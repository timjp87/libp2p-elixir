defmodule Libp2p.Ping do
  @moduledoc """
  Minimal `/ipfs/ping/1.0.0` support.

  The protocol exchanges opaque 32-byte payloads. Responders echo each payload
  verbatim, and callers can use the round trip as a cheap connection-health
  probe.
  """

  alias Libp2p.{ConnectionV2, MultistreamSelect, Protocol}

  @payload_size 32
  @inbound_timeout_ms 30_000

  @spec ping(pid(), keyword()) :: {:ok, non_neg_integer()} | {:error, term()}
  def ping(conn, opts \\ []) when is_pid(conn) do
    timeout = Keyword.get(opts, :timeout, 5_000)
    payload = Keyword.get_lazy(opts, :payload, fn -> :crypto.strong_rand_bytes(@payload_size) end)

    if valid_payload?(payload) do
      do_ping(conn, payload, timeout)
    else
      {:error, :invalid_payload}
    end
  end

  @spec handle_inbound(pid(), non_neg_integer(), binary(), binary()) :: :ok
  def handle_inbound(conn, stream_id, _proto, initial) do
    echo_loop(conn, stream_id, initial)
  end

  @spec handle_inbound(pid(), non_neg_integer(), binary()) :: :ok
  def handle_inbound(conn, stream_id, initial) do
    handle_inbound(conn, stream_id, Protocol.ping(), initial)
  end

  defp do_ping(conn, payload, timeout) do
    mss = MultistreamSelect.new_initiator([Protocol.ping()])
    {out0, mss} = MultistreamSelect.start(mss)
    started_at = System.monotonic_time(:microsecond)

    try do
      with {:ok, stream_id} <- ConnectionV2.open_stream(conn, out0),
           :ok <- ConnectionV2.set_stream_handler(conn, stream_id, self()),
           {:ok, leftover} <- negotiate(conn, stream_id, mss, timeout),
           :ok <- ConnectionV2.send_stream(conn, stream_id, payload),
           {:ok, ^payload} <- recv_pong(conn, stream_id, leftover, payload, timeout) do
        _ = ConnectionV2.close_stream(conn, stream_id)
        {:ok, System.monotonic_time(:microsecond) - started_at}
      else
        {:ok, other} ->
          {:error, {:unexpected_pong, other}}

        {:error, reason} ->
          {:error, reason}

        other ->
          {:error, other}
      end
    catch
      :exit, _reason -> {:error, :connection_closed}
    end
  end

  defp negotiate(conn, stream_id, mss, timeout) do
    receive do
      {:libp2p, :stream_data, ^conn, ^stream_id, data} ->
        {events, out, mss2} = MultistreamSelect.feed(mss, data, MapSet.new())
        if out != <<>>, do: :ok = ConnectionV2.send_stream(conn, stream_id, out)

        case Enum.find(events, &match?({:error, _}, &1)) do
          {:error, reason} ->
            {:error, {:negotiation_failed, reason}}

          _ ->
            case Enum.find(events, &match?({:selected, _}, &1)) do
              {:selected, _protocol} -> {:ok, Map.get(mss2, :buf, <<>>)}
              _ -> negotiate(conn, stream_id, mss2, timeout)
            end
        end

      {:libp2p, :stream_closed, ^conn, ^stream_id} ->
        {:error, :stream_closed}
    after
      timeout -> {:error, :timeout}
    end
  end

  defp recv_pong(conn, stream_id, buf, payload, timeout) do
    case parse_pong(buf) do
      {:ok, pong} ->
        {:ok, pong}

      :more ->
        receive do
          {:libp2p, :stream_data, ^conn, ^stream_id, data} ->
            recv_pong(conn, stream_id, buf <> data, payload, timeout)

          {:libp2p, :stream_closed, ^conn, ^stream_id} ->
            {:error, :stream_closed}
        after
          timeout -> {:error, :timeout}
        end
    end
  end

  defp echo_loop(conn, stream_id, buf) when is_binary(buf) do
    {payloads, rest} = take_payloads(buf, [])

    case echo_payloads(conn, stream_id, payloads) do
      :ok ->
        receive do
          {:libp2p, :stream_data, ^conn, ^stream_id, data} ->
            echo_loop(conn, stream_id, rest <> data)

          {:libp2p, :stream_closed, ^conn, ^stream_id} ->
            :ok
        after
          @inbound_timeout_ms ->
            _ = ConnectionV2.reset_stream(conn, stream_id)
            :ok
        end

      {:error, _reason} ->
        _ = ConnectionV2.reset_stream(conn, stream_id)
        :ok
    end
  end

  defp echo_payloads(conn, stream_id, payloads) do
    Enum.reduce_while(payloads, :ok, fn payload, :ok ->
      case ConnectionV2.send_stream(conn, stream_id, payload) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  catch
    :exit, reason -> {:error, reason}
  end

  defp parse_pong(buf) when byte_size(buf) >= @payload_size do
    <<pong::binary-size(@payload_size), _rest::binary>> = buf
    {:ok, pong}
  end

  defp parse_pong(_buf), do: :more

  defp take_payloads(buf, acc) when byte_size(buf) >= @payload_size do
    <<payload::binary-size(@payload_size), rest::binary>> = buf
    take_payloads(rest, [payload | acc])
  end

  defp take_payloads(rest, acc), do: {Enum.reverse(acc), rest}

  defp valid_payload?(payload), do: is_binary(payload) and byte_size(payload) == @payload_size
end
