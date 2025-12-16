defmodule Libp2p.PeerIdTest do
  use ExUnit.Case, async: true

  alias Libp2p.{Base58btc, Crypto.Secp256k1, Identity, PeerId}

  test "base58btc roundtrip" do
    bin = <<0, 0, 1, 2, 3, 255, 0, 10, 20, 30>>
    enc = Base58btc.encode(bin)
    assert Base58btc.decode(enc) == bin
  end

  test "peer id is multihash sha2-256 (34 bytes)" do
    id = Identity.generate_secp256k1()
    pid = id.peer_id

    assert byte_size(pid) == 34
    assert <<0x12, 0x20, _digest::binary-size(32)>> = pid

    # formatting roundtrip
    s = PeerId.to_base58(pid)
    assert PeerId.from_base58(s) == pid
  end

  test "secp256k1 pubkey compress/decompress roundtrip" do
    {_priv, pub} = Secp256k1.generate_keypair()
    c = Secp256k1.compress_pubkey(pub)
    assert byte_size(c) == 33
    pub2 = Secp256k1.decompress_pubkey(c)
    assert pub2 == pub
  end
end

