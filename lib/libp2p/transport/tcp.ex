defmodule Libp2p.Transport.Tcp do
  @moduledoc """
  TCP transport helpers for libp2p.

  Uses `:gen_tcp` in passive mode (`active: false`) and raw packets.
  """

  @type socket :: port()

  @default_listen_opts [:binary, packet: :raw, active: false, reuseaddr: true, nodelay: true]
  @default_dial_opts [:binary, packet: :raw, active: false, nodelay: true]

  @spec listen(:inet.ip_address(), :inet.port_number(), keyword()) :: {:ok, socket()} | {:error, term()}
  def listen(ip, port, opts \\ []) do
    backlog = Keyword.get(opts, :backlog, 128)
    tcp_opts = Keyword.get(opts, :tcp_opts, [])

    :gen_tcp.listen(
      port,
      @default_listen_opts ++ tcp_opts ++ [ip: ip, backlog: backlog]
    )
  end

  @spec accept(socket(), timeout()) :: {:ok, socket()} | {:error, term()}
  def accept(listener, timeout \\ 5_000) do
    :gen_tcp.accept(listener, timeout)
  end

  @spec dial(:inet.ip_address() | charlist(), :inet.port_number(), keyword()) :: {:ok, socket()} | {:error, term()}
  def dial(host, port, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 5_000)
    tcp_opts = Keyword.get(opts, :tcp_opts, [])
    :gen_tcp.connect(host, port, @default_dial_opts ++ tcp_opts, timeout)
  end

  @spec close(socket()) :: :ok
  def close(sock), do: :gen_tcp.close(sock)

  @spec send(socket(), iodata()) :: :ok | {:error, term()}
  def send(sock, data), do: :gen_tcp.send(sock, data)

  @spec recv(socket(), non_neg_integer(), timeout()) :: {:ok, binary()} | {:error, term()}
  def recv(sock, len, timeout \\ 5_000), do: :gen_tcp.recv(sock, len, timeout)

  @spec peername(socket()) :: {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}
  def peername(sock), do: :inet.peername(sock)

  @spec sockname(socket()) :: {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}
  def sockname(sock), do: :inet.sockname(sock)
end
