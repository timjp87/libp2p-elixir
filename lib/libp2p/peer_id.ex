defmodule Libp2p.PeerId do
  @moduledoc """
  PeerId derivation and formatting.

  PeerId bytes are a multihash of the libp2p-crypto protobuf-encoded public key.
  For this minimal implementation we use sha2-256 multihash.
  """

  alias Libp2p.Base58btc
  alias Libp2p.Crypto.PublicKeyPB

  # multihash codes (single-byte varints for the ones we use)
  @mh_sha2_256 0x12
  @sha2_256_len 32

  @type t :: binary()

  @spec from_secp256k1_pubkey_compressed(binary()) :: t()
  def from_secp256k1_pubkey_compressed(pubkey33) when is_binary(pubkey33) and byte_size(pubkey33) == 33 do
    pk_pb = PublicKeyPB.encode_public_key(:secp256k1, pubkey33)
    digest = :crypto.hash(:sha256, pk_pb)
    <<@mh_sha2_256, @sha2_256_len, digest::binary>>
  end

  @spec to_base58(t()) :: binary()
  def to_base58(peer_id_bytes) when is_binary(peer_id_bytes) do
    Base58btc.encode(peer_id_bytes)
  end

  @spec from_base58(binary()) :: t()
  def from_base58(str) when is_binary(str) do
    Base58btc.decode(str)
  end
end

