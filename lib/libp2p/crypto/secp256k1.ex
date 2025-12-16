defmodule Libp2p.Crypto.Secp256k1 do
  @moduledoc """
  secp256k1 identity keys.

  Uses OTP `:crypto` primitives (OpenSSL-backed) for key generation and ECDSA.
  """

  @type privkey :: binary()
  @type pubkey_uncompressed :: binary()
  @type pubkey_compressed :: binary()

  @spec generate_keypair() :: {privkey(), pubkey_uncompressed()}
  def generate_keypair do
    # Returns {public_key, private_key}
    {pub, priv} = :crypto.generate_key(:ecdh, :secp256k1)
    {priv, pub}
  end

  @spec compress_pubkey(pubkey_uncompressed()) :: pubkey_compressed()
  def compress_pubkey(<<4, x::binary-size(32), y::binary-size(32)>>) do
    y_int = :binary.decode_unsigned(y)
    prefix = if rem(y_int, 2) == 0, do: 0x02, else: 0x03
    <<prefix, x::binary>>
  end

  @spec decompress_pubkey(pubkey_compressed()) :: pubkey_uncompressed()
  def decompress_pubkey(<<prefix, x_bytes::binary-size(32)>>) when prefix in [0x02, 0x03] do
    # p % 4 == 3 for secp256k1, so sqrt(y2) = y2^((p+1)/4) mod p
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    x = :binary.decode_unsigned(x_bytes)
    y2 = rem(rem(x * x, p) * x + 7, p)
    exp = div(p + 1, 4)
    y = :crypto.mod_pow(:binary.encode_unsigned(y2), :binary.encode_unsigned(exp), :binary.encode_unsigned(p)) |> :binary.decode_unsigned()

    is_odd = rem(y, 2) == 1
    want_odd = prefix == 0x03
    y = if is_odd == want_odd, do: y, else: p - y
    y_bytes = left_pad32(:binary.encode_unsigned(y))
    <<4, x_bytes::binary, y_bytes::binary>>
  end

  @spec sign(privkey(), binary()) :: binary()
  def sign(priv, msg) when is_binary(priv) and is_binary(msg) do
    :crypto.sign(:ecdsa, :sha256, msg, [priv, :secp256k1])
  end

  @spec verify(pubkey_uncompressed(), binary(), binary()) :: boolean()
  def verify(pub, msg, sig) when is_binary(pub) and is_binary(msg) and is_binary(sig) do
    :crypto.verify(:ecdsa, :sha256, msg, sig, [pub, :secp256k1])
  end

  defp left_pad32(bin) do
    if byte_size(bin) > 32, do: raise(ArgumentError, "expected <=32 bytes")
    :binary.copy(<<0>>, 32 - byte_size(bin)) <> bin
  end
end

