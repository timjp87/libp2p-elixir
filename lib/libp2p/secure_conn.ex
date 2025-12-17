defmodule Libp2p.SecureConn do
  @moduledoc """
  Noise-secured connection wrapper.

  - Performs Noise transport message framing (2-byte big-endian length prefix).
  - Encrypts/decrypts payloads using `Libp2p.Noise.transport_encrypt/3` and
    `Libp2p.Noise.transport_decrypt/3`.

  This intentionally exposes a small interface; the Swarm/Connection process
  owns the socket and calls these helpers.
  """

  alias Libp2p.Noise
  alias Libp2p.Transport.Tcp

  @type cipher_state :: %{k: binary() | nil, n: non_neg_integer()}
  @type t :: %__MODULE__{
          socket: Tcp.socket(),
          cs_in: cipher_state(),
          cs_out: cipher_state(),
          recv_buf: binary()
        }

  defstruct [:socket, :cs_in, :cs_out, recv_buf: <<>>]

  @spec new(Tcp.socket(), cipher_state(), cipher_state()) :: t()
  def new(socket, cs_in, cs_out) do
    %__MODULE__{socket: socket, cs_in: cs_in, cs_out: cs_out, recv_buf: <<>>}
  end

  @spec send(t(), binary()) :: {:ok, t()} | {:error, term()}
  def send(%__MODULE__{} = c, bytes) when is_binary(bytes) do
    # Noise transport messages have a 2-byte BE length prefix and max length 65535.
    do_send(c, bytes)
  end

  defp do_send(c, <<>>), do: {:ok, c}

  defp do_send(%__MODULE__{} = c, bytes) do
    # Leave room for tag; Noise module does not enforce size here but framing does.
    chunk = binary_part(bytes, 0, min(byte_size(bytes), 65_535))
    rest = binary_part(bytes, byte_size(chunk), byte_size(bytes) - byte_size(chunk))

    {ct, cs_out2} = Noise.transport_encrypt(c.cs_out, chunk)
    frame = Noise.frame(ct)

    case Tcp.send(c.socket, frame) do
      :ok -> do_send(%{c | cs_out: cs_out2}, rest)
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Append raw encrypted bytes received from the socket.
  """
  @spec ingest(t(), binary()) :: t()
  def ingest(%__MODULE__{} = c, data) when is_binary(data) do
    %{c | recv_buf: c.recv_buf <> data}
  end

  @doc """
  Decrypt as many complete Noise transport messages as are currently buffered.

  Returns `{plaintext_messages, conn2}` where each plaintext message corresponds
  to one Noise transport message.
  """
  @spec drain(t()) :: {[binary()], t()}
  def drain(%__MODULE__{} = c) do
    do_drain(c, [])
  end

  defp do_drain(%__MODULE__{} = c, acc) do
    case Noise.deframe(c.recv_buf) do
      {msg, rest} ->
        {pt, cs_in2} = Noise.transport_decrypt(c.cs_in, msg)
        do_drain(%{c | recv_buf: rest, cs_in: cs_in2}, [pt | acc])

      :more ->
        {Enum.reverse(acc), c}
    end
  end

  @doc """
  Receive *some* plaintext bytes (one Noise transport message).

  Returns `{bytes, conn2}` where `bytes` may be empty only on protocol errors (raised).
  """
  @spec recv(t(), timeout()) :: {:ok, binary(), t()} | {:error, term()}
  def recv(%__MODULE__{} = c, timeout \\ 5_000) do
    with {:ok, msg, c2} <- recv_frame(c, timeout) do
      {pt, cs_in2} = Noise.transport_decrypt(c2.cs_in, msg)
      {:ok, pt, %{c2 | cs_in: cs_in2}}
    end
  end

  # --- framing ---

  defp recv_frame(%__MODULE__{} = c, timeout) do
    case Noise.deframe(c.recv_buf) do
      {msg, rest} ->
        {:ok, msg, %{c | recv_buf: rest}}

      :more ->
        case Tcp.recv(c.socket, 0, timeout) do
          {:ok, data} -> recv_frame(%{c | recv_buf: c.recv_buf <> data}, timeout)
          {:error, reason} -> {:error, reason}
        end
    end
  end
end
