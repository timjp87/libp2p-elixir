defmodule Libp2p.StreamNegotiator do
  @moduledoc """
  Multistream-select negotiation on top of an established yamux stream.

  Uses `Libp2p.Connection.stream_send/3` and `stream_recv/3` as the transport.
  """

  alias Libp2p.{Connection, MultistreamSelect}

  @type proto_id :: binary()

  @spec negotiate_inbound(pid(), non_neg_integer(), MapSet.t(proto_id()), keyword()) ::
          {:ok, proto_id(), binary()} | {:error, term()}
  def negotiate_inbound(conn, stream_id, supported, opts \\ []) do
    st = MultistreamSelect.new_responder()
    negotiate(conn, stream_id, st, supported, opts)
  end

  @spec negotiate_outbound(pid(), non_neg_integer(), [proto_id()], MapSet.t(proto_id()), keyword()) ::
          {:ok, proto_id(), binary()} | {:error, term()}
  def negotiate_outbound(conn, stream_id, proposals, supported, opts \\ []) do
    st = MultistreamSelect.new_initiator(proposals)
    negotiate(conn, stream_id, st, supported, opts)
  end

  defp negotiate(conn, stream_id, st, supported, opts) do
    timeout = Keyword.get(opts, :timeout, 5_000)

    # Enable active mode (Push)
    case try_set_handler(conn, stream_id) do
      :ok ->
        {out0, st} = MultistreamSelect.start(st)
        case Connection.stream_send(conn, stream_id, out0) do
          :ok -> loop(conn, stream_id, st, supported, timeout)
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} -> {:error, reason}
    end
  end

  defp try_set_handler(conn, stream_id) do
    try do
      Libp2p.Connection.set_stream_handler(conn, stream_id, self())
    rescue
      # Fallback for very old implementations if any
      _ -> :ok
    end
  end

  defp loop(conn, stream_id, st, supported, timeout) do
    if st.selected != nil do
      {:ok, st.selected, st.buf}
    else
      # Receive from mailbox (Push mode)
      msg =
        receive do
          {:libp2p, :stream_data, ^conn, ^stream_id, data} -> {:ok, data}
          {:libp2p, :stream_closed, ^conn, ^stream_id} -> {:error, :closed}
          {:libp2p, :stream_reset, ^conn, ^stream_id} -> {:error, :reset}
        after
          timeout -> {:error, :timeout}
        end

      case msg do
        {:ok, data} ->
          {events, out, st2} = MultistreamSelect.feed(st, data, supported)
          send_result =
            if out == <<>> do
              :ok
            else
              Connection.stream_send(conn, stream_id, out)
            end

          if send_result != :ok do
            {:error, send_result}
          else
            case Enum.find(events, fn
                   {:selected, _} -> true
                   {:error, _} -> true
                   _ -> false
                 end) do
              {:selected, proto} -> {:ok, proto, st2.buf}
              {:error, reason} -> {:error, reason}
              _ -> loop(conn, stream_id, st2, supported, timeout)
            end
          end

        {:error, reason} ->
          {:error, reason}
      end
    end
  end
end
