defmodule Libp2p.NoisePayloadSignatureTest do
  use ExUnit.Case, async: true

  alias Libp2p.{Identity, Noise, Protobuf}
  alias Libp2p.Crypto.{PublicKeyPB, Secp256k1}

  @sig_prefix "noise-libp2p-static-key:"

  defp payload_bin(identity_key_pb, sig, ext_bin \\ nil) do
    base =
      Protobuf.encode_len_field(1, identity_key_pb) <>
        Protobuf.encode_len_field(2, sig)

    if is_binary(ext_bin) do
      base <> Protobuf.encode_len_field(4, ext_bin)
    else
      base
    end
  end

  test "valid signature verifies against noise static pubkey" do
    id = Identity.generate_secp256k1()
    {noise_pub32, _noise_priv} = :crypto.generate_key(:ecdh, :x25519)

    identity_key_pb = PublicKeyPB.encode_public_key(:secp256k1, id.pubkey_compressed)
    sig = Secp256k1.sign_bitcoin(id.privkey, @sig_prefix <> noise_pub32)

    pb = payload_bin(identity_key_pb, sig)

    assert {:secp256k1, pub33, _} = Noise.__verify_handshake_payload__(pb, noise_pub32)
    assert pub33 == id.pubkey_compressed
  end

  test "invalid signature is rejected" do
    id = Identity.generate_secp256k1()
    {noise_pub32, _noise_priv} = :crypto.generate_key(:ecdh, :x25519)

    identity_key_pb = PublicKeyPB.encode_public_key(:secp256k1, id.pubkey_compressed)
    sig = Secp256k1.sign_bitcoin(id.privkey, @sig_prefix <> noise_pub32)

    # flip one byte
    <<head::binary-size(byte_size(sig) - 1), last::unsigned-integer-size(8)>> = sig
    bad_sig = head <> <<Bitwise.bxor(last, 0x01)>>

    pb = payload_bin(identity_key_pb, bad_sig)

    assert_raise ArgumentError, ~r/invalid noise-libp2p static key signature/, fn ->
      Noise.__verify_handshake_payload__(pb, noise_pub32)
    end
  end

  test "signature must bind to the received noise static key" do
    id = Identity.generate_secp256k1()
    {noise_pub32_a, _} = :crypto.generate_key(:ecdh, :x25519)
    {noise_pub32_b, _} = :crypto.generate_key(:ecdh, :x25519)

    identity_key_pb = PublicKeyPB.encode_public_key(:secp256k1, id.pubkey_compressed)
    sig_over_b = Secp256k1.sign_bitcoin(id.privkey, @sig_prefix <> noise_pub32_b)

    pb = payload_bin(identity_key_pb, sig_over_b)

    assert_raise ArgumentError, ~r/invalid noise-libp2p static key signature/, fn ->
      Noise.__verify_handshake_payload__(pb, noise_pub32_a)
    end
  end

  test "extensions field (4) is tolerated and does not affect signature verification" do
    id = Identity.generate_secp256k1()
    {noise_pub32, _noise_priv} = :crypto.generate_key(:ecdh, :x25519)

    identity_key_pb = PublicKeyPB.encode_public_key(:secp256k1, id.pubkey_compressed)
    sig = Secp256k1.sign_bitcoin(id.privkey, @sig_prefix <> noise_pub32)

    # Use valid encoded extensions (empty map) instead of random bytes
    ext = Libp2p.Noise.HandshakePayloadPB.encode_extensions(%{stream_muxers: []})
    pb = payload_bin(identity_key_pb, sig, ext)

    assert {:secp256k1, pub33, _} = Noise.__verify_handshake_payload__(pb, noise_pub32)
    assert pub33 == id.pubkey_compressed
  end
end
