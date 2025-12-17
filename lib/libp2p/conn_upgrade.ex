defmodule Libp2p.ConnUpgrade do
  @moduledoc """
  Connection upgrade pipeline: multistream-select → noise → multistream-select → yamux.

  This module performs the on-wire negotiation and returns a `Libp2p.SecureConn`.
  """

  alias Libp2p.{Identity, MultistreamSelect, Noise, Protocol, SecureConn}
  alias Libp2p.Transport.Tcp
  alias Libp2p.Yamux.Session

  @type socket :: Tcp.socket()
  @type role :: :initiator | :responder

  @spec upgrade_outbound(socket(), Identity.t(), keyword()) :: {:ok, SecureConn.t(), Session.t(), binary()} | {:error, term()}
  def upgrade_outbound(sock, %Identity{} = id, opts \\ []) do
    upgrade(sock, :initiator, id, opts)
  end

  @spec upgrade_inbound(socket(), Identity.t(), keyword()) :: {:ok, SecureConn.t(), Session.t(), binary()} | {:error, term()}
  def upgrade_inbound(sock, %Identity{} = id, opts \\ []) do
    upgrade(sock, :responder, id, opts)
  end

  defp upgrade(sock, role, %Identity{} = id, opts) do
    timeout = Keyword.get(opts, :timeout, 10_000)

    with {:ok, sock} <- set_passive(sock),
         {:ok, noise_buf} <- negotiate_security(sock, role, timeout),
         {:ok, secure, remote_peer_id} <- run_noise(sock, role, id, timeout, noise_buf),
         {:ok, yamux_buf, secure} <- negotiate_muxer(secure, role, timeout) do
      # Start yamux session (client/server role is inverted from initiator/responder in practice;
      # we keep it simple: initiator acts as yamux client).
      yamux_role = if role == :initiator, do: :client, else: :server
      yamux = Session.new(yamux_role)
      {_, _out, yamux2} = Session.feed(yamux, yamux_buf)
      {:ok, secure, yamux2, remote_peer_id}
    else
      {:error, _} = err -> err
      other -> {:error, other}
    end
  end

  defp set_passive(sock) do
    case :inet.setopts(sock, active: false) do
      :ok -> {:ok, sock}
      {:error, reason} -> {:error, reason}
    end
  end

  # --- security negotiation (raw socket MSS) ---

  defp negotiate_security(sock, role, timeout) do
    noise = Protocol.noise()
    proposals = [noise]
    supported = MapSet.new([noise])

    case mss_negotiate(sock, role, proposals, supported, timeout) do
      {:ok, ^noise, buf} -> {:ok, buf}
      {:ok, other, _buf} -> {:error, {:unexpected_security_selected, other}}
      {:error, _} = err -> err
    end
  end

  # --- noise handshake ---

  defp run_noise(sock, role, %Identity{} = id, timeout, buf0) do
    case role do
      :initiator ->
        st0 = Noise.new(:initiator, id)
        {msg1, st1} = Noise.initiator_msg1(st0)
        :ok = Tcp.send(sock, Noise.frame(msg1))

        with {:ok, msg2, rest2} <- recv_noise_frame(sock, timeout, buf0) do
          {msg3, st2, {cs_out, cs_in}} = Noise.initiator_msg3(st1, msg2)
          :ok = Tcp.send(sock, Noise.frame(msg3))
          {:ok, %{SecureConn.new(sock, cs_in, cs_out) | recv_buf: rest2}, remote_peer_id_from_noise!(st2)}
        end

      :responder ->
        st0 = Noise.new(:responder, id)

        with {:ok, msg1, rest1} <- recv_noise_frame(sock, timeout, buf0) do
          {msg2, st1} = Noise.responder_msg2(st0, msg1)
          :ok = Tcp.send(sock, Noise.frame(msg2))

          with {:ok, msg3, rest3} <- recv_noise_frame(sock, timeout, rest1) do
            {st2, {cs_in, cs_out}} = Noise.responder_finish(st1, msg3)
            {:ok, %{SecureConn.new(sock, cs_in, cs_out) | recv_buf: rest3}, remote_peer_id_from_noise!(st2)}
          end
        end
    end
  end

  defp remote_peer_id_from_noise!(%{remote_identity_key: {:secp256k1, pubkey33}}) when is_binary(pubkey33) do
    Libp2p.PeerId.from_secp256k1_pubkey_compressed(pubkey33)
  end

  defp remote_peer_id_from_noise!(%{remote_identity_key: other}),
    do: raise(ArgumentError, "unsupported remote identity key from noise: #{inspect(other)}")

  defp recv_noise_frame(sock, timeout, buf) do
    case Noise.deframe(buf) do
      {msg, rest} ->
        {:ok, msg, rest}

      :more ->
        case Tcp.recv(sock, 0, timeout) do
          {:ok, data} -> recv_noise_frame(sock, timeout, buf <> data)
          {:error, reason} -> {:error, reason}
        end
    end
  end

  # (initiator variant probing removed; snow-compatible handshake is deterministic)

  # --- muxer negotiation (encrypted MSS) ---

  defp negotiate_muxer(%SecureConn{} = secure, role, timeout) do
    yamux = Protocol.yamux()
    proposals = [yamux]
    supported = MapSet.new([yamux])

    case mss_negotiate_secure(secure, role, proposals, supported, timeout) do
      {:ok, ^yamux, secure2, buf} -> {:ok, buf, secure2}
      {:ok, other, _secure2, _buf} -> {:error, {:unexpected_muxer_selected, other}}
      {:error, _} = err -> err
    end
  end

  # --- MSS helpers ---

  defp mss_negotiate(sock, role, proposals, supported, timeout) do
    st =
      case role do
        :initiator -> MultistreamSelect.new_initiator(proposals)
        :responder -> MultistreamSelect.new_responder()
      end

    {out0, st} = MultistreamSelect.start(st)
    :ok = Tcp.send(sock, out0)
    loop_mss_socket(sock, st, supported, timeout)
  end

  defp loop_mss_socket(sock, st, supported, timeout) do
    case st.selected do
      nil ->
        case Tcp.recv(sock, 0, timeout) do
          {:ok, data} ->
            {events, out, st2} = MultistreamSelect.feed(st, data, supported)
            :ok = if out == <<>>, do: :ok, else: Tcp.send(sock, out)

            case Enum.find(events, fn
                   {:selected, _} -> true
                   {:error, _} -> true
                   _ -> false
                 end) do
              {:selected, proto} -> {:ok, proto, st2.buf}
              {:error, reason} -> {:error, reason}
              _ -> loop_mss_socket(sock, st2, supported, timeout)
            end

          {:error, reason} ->
            {:error, reason}
        end

      proto ->
        {:ok, proto, st.buf}
    end
  end

  defp mss_negotiate_secure(%SecureConn{} = c0, role, proposals, supported, timeout) do
    st =
      case role do
        :initiator -> MultistreamSelect.new_initiator(proposals)
        :responder -> MultistreamSelect.new_responder()
      end

    {out0, st} = MultistreamSelect.start(st)
    {:ok, c1} = SecureConn.send(c0, out0)
    loop_mss_secure(c1, st, supported, timeout)
  end

  defp loop_mss_secure(%SecureConn{} = c, st, supported, timeout) do
    if st.selected != nil do
      {:ok, st.selected, c, st.buf}
    else
      with {:ok, data, c2} <- SecureConn.recv(c, timeout) do
        {events, out, st2} = MultistreamSelect.feed(st, data, supported)
        c3 =
          if out == <<>> do
            c2
          else
            case SecureConn.send(c2, out) do
              {:ok, c3} -> c3
              {:error, reason} -> throw({:mss_send_error, reason})
            end
          end

        case Enum.find(events, fn
               {:selected, _} -> true
               {:error, _} -> true
               _ -> false
             end) do
          {:selected, proto} -> {:ok, proto, c3, st2.buf}
          {:error, reason} -> {:error, reason}
          _ -> loop_mss_secure(c3, st2, supported, timeout)
        end
      end
    end
  catch
    {:mss_send_error, reason} -> {:error, reason}
  end
end
