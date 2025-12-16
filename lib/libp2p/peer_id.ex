defmodule Libp2p.PeerId do
  @moduledoc """
  PeerId derivation and formatting.

  PeerId bytes are a multihash of the libp2p-crypto protobuf-encoded public key.

  Per `peer-ids/peer-ids.md`:
  - If the protobuf-encoded public key is **<= 42 bytes**, use the **identity** multihash.
  - Otherwise, use **sha2-256** multihash.
  """

  alias Libp2p.Base58btc
  alias Libp2p.Crypto.PublicKeyPB
  alias Libp2p.Varint

  # multihash codes (varints; these fit in 1 byte for our use)
  @mh_identity 0x00
  @mh_sha2_256 0x12
  @sha2_256_len 32
  @identity_max 42

  @type t :: binary()

  @spec from_secp256k1_pubkey_compressed(binary()) :: t()
  def from_secp256k1_pubkey_compressed(pubkey33) when is_binary(pubkey33) and byte_size(pubkey33) == 33 do
    pk_pb = PublicKeyPB.encode_public_key(:secp256k1, pubkey33)
    from_public_key_protobuf(pk_pb)
  end

  @spec from_public_key_protobuf(binary()) :: t()
  def from_public_key_protobuf(pk_pb) when is_binary(pk_pb) do
    if byte_size(pk_pb) <= @identity_max do
      # identity multihash: code + length(varint) + bytes
      Varint.encode_u64(@mh_identity) <> Varint.encode_u64(byte_size(pk_pb)) <> pk_pb
    else
      digest = :crypto.hash(:sha256, pk_pb)
      Varint.encode_u64(@mh_sha2_256) <> Varint.encode_u64(@sha2_256_len) <> digest
    end
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
