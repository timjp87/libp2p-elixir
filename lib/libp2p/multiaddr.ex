defmodule Libp2p.Multiaddr do
  @moduledoc """
  Minimal Multiaddr implementation (binary codec + a small parser).

  Ethereum consensus clients mostly need `/ip4|ip6/.../tcp/...` (and often see
  additional components like `/p2p/...`, `/udp/.../quic-v1`, `/tls`, `/ws` in peer
  advertisements). We implement enough of the multiaddr table to:
  - encode/decode common addresses seen in the wild
  - extract a `:inet` tuple + port for TCP dialing/listening
  """

  alias Libp2p.Varint
  alias Libp2p.PeerId

  @type proto ::
          {:ip4, :inet.ip4_address()}
          | {:ip6, :inet.ip6_address()}
          | {:tcp, :inet.port_number()}
          | {:udp, :inet.port_number()}
          | {:dns, binary()}
          | {:dns4, binary()}
          | {:dns6, binary()}
          | {:dnsaddr, binary()}
          | {:p2p, binary()}
          | {:quic, nil}
          | {:quic_v1, nil}
          | {:webtransport, nil}
          | {:tls, nil}
          | {:ws, nil}
          | {:wss, nil}
          | {:certhash, binary()}

  @type t :: %__MODULE__{protos: [proto()], bytes: binary()}

  defstruct [:protos, :bytes]

  # Multicodec codes (subset).
  @code_ip4 4
  @code_tcp 6
  @code_dns 53
  @code_dns4 54
  @code_dns6 55
  @code_dnsaddr 56
  @code_udp 273
  @code_quic 460
  @code_quic_v1 461
  @code_webtransport 465
  @code_certhash 466
  @code_tls 448
  @code_ws 477
  @code_wss 478
  @code_ip6 41
  @code_p2p 421

  @spec new([proto()]) :: t()
  def new(protos) when is_list(protos) do
    bytes = encode_protos(protos)
    %__MODULE__{protos: protos, bytes: bytes}
  end

  @spec to_bytes(t()) :: binary()
  def to_bytes(%__MODULE__{bytes: b}), do: b

  @spec from_bytes(binary()) :: t()
  def from_bytes(bin) when is_binary(bin) do
    {protos, rest} = decode_protos(bin, [])
    if rest != <<>>, do: raise(ArgumentError, "trailing bytes in multiaddr")
    %__MODULE__{protos: protos, bytes: bin}
  end

  @doc """
  Parse a multiaddr string like `/ip4/1.2.3.4/tcp/9000(/p2p/<peerid>)`.
  """
  @spec from_string(binary()) :: t()
  def from_string(str) when is_binary(str) do
    parts =
      str
      |> String.trim()
      |> String.split("/", trim: true)

    protos =
      parts
      |> parse_parts([])
      |> Enum.reverse()

    new(protos)
  end

  @doc """
  Best-effort conversion to a multiaddr string. Unknown/unsupported protos are not represented.
  """
  @spec to_string(t()) :: binary()
  def to_string(%__MODULE__{protos: protos}) do
    "/" <>
      (protos
       |> Enum.map(&proto_to_string_part/1)
       |> Enum.join("/"))
  end

  @doc """
  Extract a TCP socket address from a multiaddr (first ip4/ip6 + tcp).
  Returns `{:ok, {ip, port}}` or `{:error, reason}`.
  """
  @spec to_tcp_socketaddr(t()) :: {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}
  def to_tcp_socketaddr(%__MODULE__{protos: protos}) do
    ip =
      Enum.find_value(protos, fn
        {:ip4, a} -> a
        {:ip6, a} -> a
        _ -> nil
      end)

    port = Enum.find_value(protos, fn {:tcp, p} -> p; _ -> nil end)

    cond do
      ip == nil -> {:error, :no_ip}
      port == nil -> {:error, :no_tcp}
      true -> {:ok, {ip, port}}
    end
  end

  @spec from_tcp_socketaddr(:inet.ip_address(), :inet.port_number()) :: t()
  def from_tcp_socketaddr(ip, port) when is_integer(port) and port >= 0 and port <= 65_535 do
    ip_proto =
      case ip do
        {_, _, _, _} -> {:ip4, ip}
        {_, _, _, _, _, _, _, _} -> {:ip6, ip}
      end

    new([ip_proto, {:tcp, port}])
  end

  # --- string parsing ---

  defp parse_parts([], acc), do: acc

  defp parse_parts(["ip4", ip, "tcp", port | rest], acc) do
    {:ok, ip4} = :inet.parse_ipv4_address(to_charlist(ip))
    parse_parts(rest, [{:tcp, String.to_integer(port)}, {:ip4, ip4} | acc])
  end

  defp parse_parts(["ip6", ip, "tcp", port | rest], acc) do
    {:ok, ip6} = :inet.parse_ipv6_address(to_charlist(ip))
    parse_parts(rest, [{:tcp, String.to_integer(port)}, {:ip6, ip6} | acc])
  end

  defp parse_parts(["dns", host, "tcp", port | rest], acc),
    do: parse_parts(rest, [{:tcp, String.to_integer(port)}, {:dns, host} | acc])

  defp parse_parts(["dns4", host, "tcp", port | rest], acc),
    do: parse_parts(rest, [{:tcp, String.to_integer(port)}, {:dns4, host} | acc])

  defp parse_parts(["dns6", host, "tcp", port | rest], acc),
    do: parse_parts(rest, [{:tcp, String.to_integer(port)}, {:dns6, host} | acc])

  defp parse_parts(["p2p", peer | rest], acc) do
    peer_bytes = PeerId.from_base58(peer)
    parse_parts(rest, [{:p2p, peer_bytes} | acc])
  end

  defp parse_parts([p | _], _acc),
    do: raise(ArgumentError, "unsupported multiaddr string component: #{inspect(p)}")

  defp proto_to_string_part({:ip4, {a, b, c, d}}), do: "ip4/#{a}.#{b}.#{c}.#{d}"
  defp proto_to_string_part({:ip6, ip6}), do: "ip6/#{:inet.ntoa(ip6)}"
  defp proto_to_string_part({:tcp, port}), do: "tcp/#{port}"
  defp proto_to_string_part({:udp, port}), do: "udp/#{port}"
  defp proto_to_string_part({:dns, host}), do: "dns/#{host}"
  defp proto_to_string_part({:dns4, host}), do: "dns4/#{host}"
  defp proto_to_string_part({:dns6, host}), do: "dns6/#{host}"
  defp proto_to_string_part({:dnsaddr, host}), do: "dnsaddr/#{host}"
  defp proto_to_string_part({:p2p, peer_bytes}), do: "p2p/#{PeerId.to_base58(peer_bytes)}"
  defp proto_to_string_part({:quic, _}), do: "quic"
  defp proto_to_string_part({:quic_v1, _}), do: "quic-v1"
  defp proto_to_string_part({:webtransport, _}), do: "webtransport"
  defp proto_to_string_part({:tls, _}), do: "tls"
  defp proto_to_string_part({:ws, _}), do: "ws"
  defp proto_to_string_part({:wss, _}), do: "wss"
  defp proto_to_string_part({:certhash, mh}), do: "certhash/#{Base.encode16(mh, case: :lower)}"

  # --- binary encoding/decoding ---

  defp encode_protos(protos) do
    protos
    |> Enum.map(&encode_proto/1)
    |> IO.iodata_to_binary()
  end

  defp encode_proto({:ip4, {a, b, c, d}}), do: Varint.encode_u64(@code_ip4) <> <<a, b, c, d>>
  defp encode_proto({:ip6, ip6}), do: Varint.encode_u64(@code_ip6) <> ip6_to_bytes(ip6)
  defp encode_proto({:tcp, port}), do: Varint.encode_u64(@code_tcp) <> <<port::unsigned-big-integer-size(16)>>
  defp encode_proto({:udp, port}), do: Varint.encode_u64(@code_udp) <> <<port::unsigned-big-integer-size(16)>>

  defp encode_proto({:dns, host}), do: Varint.encode_u64(@code_dns) <> Varint.encode_u64(byte_size(host)) <> host
  defp encode_proto({:dns4, host}), do: Varint.encode_u64(@code_dns4) <> Varint.encode_u64(byte_size(host)) <> host
  defp encode_proto({:dns6, host}), do: Varint.encode_u64(@code_dns6) <> Varint.encode_u64(byte_size(host)) <> host
  defp encode_proto({:dnsaddr, host}), do: Varint.encode_u64(@code_dnsaddr) <> Varint.encode_u64(byte_size(host)) <> host

  defp encode_proto({:p2p, peer_bytes}), do: Varint.encode_u64(@code_p2p) <> Varint.encode_u64(byte_size(peer_bytes)) <> peer_bytes
  defp encode_proto({:certhash, mh}), do: Varint.encode_u64(@code_certhash) <> Varint.encode_u64(byte_size(mh)) <> mh

  defp encode_proto({:quic, _}), do: Varint.encode_u64(@code_quic)
  defp encode_proto({:quic_v1, _}), do: Varint.encode_u64(@code_quic_v1)
  defp encode_proto({:webtransport, _}), do: Varint.encode_u64(@code_webtransport)
  defp encode_proto({:tls, _}), do: Varint.encode_u64(@code_tls)
  defp encode_proto({:ws, _}), do: Varint.encode_u64(@code_ws)
  defp encode_proto({:wss, _}), do: Varint.encode_u64(@code_wss)

  defp encode_proto(other), do: raise(ArgumentError, "unsupported multiaddr proto: #{inspect(other)}")

  defp decode_protos(<<>>, acc), do: {Enum.reverse(acc), <<>>}

  defp decode_protos(bin, acc) do
    {code, rest} = Varint.decode_u64(bin)

    case code do
      @code_ip4 ->
        <<a, b, c, d, rest2::binary>> = rest
        decode_protos(rest2, [{:ip4, {a, b, c, d}} | acc])

      @code_ip6 ->
        <<addr::binary-size(16), rest2::binary>> = rest
        decode_protos(rest2, [{:ip6, decode_ip6_bytes!(addr)} | acc])

      @code_tcp ->
        <<port::unsigned-big-integer-size(16), rest2::binary>> = rest
        decode_protos(rest2, [{:tcp, port} | acc])

      @code_udp ->
        <<port::unsigned-big-integer-size(16), rest2::binary>> = rest
        decode_protos(rest2, [{:udp, port} | acc])

      @code_dns ->
        {host, rest2} = decode_len(rest)
        decode_protos(rest2, [{:dns, host} | acc])

      @code_dns4 ->
        {host, rest2} = decode_len(rest)
        decode_protos(rest2, [{:dns4, host} | acc])

      @code_dns6 ->
        {host, rest2} = decode_len(rest)
        decode_protos(rest2, [{:dns6, host} | acc])

      @code_dnsaddr ->
        {host, rest2} = decode_len(rest)
        decode_protos(rest2, [{:dnsaddr, host} | acc])

      @code_p2p ->
        {peer, rest2} = decode_len(rest)
        decode_protos(rest2, [{:p2p, peer} | acc])

      @code_certhash ->
        {mh, rest2} = decode_len(rest)
        decode_protos(rest2, [{:certhash, mh} | acc])

      @code_quic ->
        decode_protos(rest, [{:quic, nil} | acc])

      @code_quic_v1 ->
        decode_protos(rest, [{:quic_v1, nil} | acc])

      @code_webtransport ->
        decode_protos(rest, [{:webtransport, nil} | acc])

      @code_tls ->
        decode_protos(rest, [{:tls, nil} | acc])

      @code_ws ->
        decode_protos(rest, [{:ws, nil} | acc])

      @code_wss ->
        decode_protos(rest, [{:wss, nil} | acc])

      other ->
        raise(ArgumentError, "unsupported multiaddr protocol code #{other}")
    end
  end

  defp decode_len(bin) do
    {len, rest} = Varint.decode_u64(bin)
    if byte_size(rest) < len, do: raise(ArgumentError, "truncated multiaddr string payload")
    <<data::binary-size(len), rest2::binary>> = rest
    {data, rest2}
  end

  defp decode_ip6_bytes!(<<_::binary-size(16)>> = b) do
    <<a::16, b2::16, c::16, d::16, e::16, f::16, g::16, h::16>> = b
    {a, b2, c, d, e, f, g, h}
  end

  defp ip6_to_bytes({a, b2, c, d, e, f, g, h}) do
    <<a::unsigned-big-integer-size(16), b2::unsigned-big-integer-size(16), c::unsigned-big-integer-size(16),
      d::unsigned-big-integer-size(16), e::unsigned-big-integer-size(16), f::unsigned-big-integer-size(16),
      g::unsigned-big-integer-size(16), h::unsigned-big-integer-size(16)>>
  end
end
