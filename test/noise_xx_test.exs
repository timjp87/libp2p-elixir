defmodule Libp2p.NoiseXXTest do
  use ExUnit.Case, async: true

  alias Libp2p.{Identity, Noise}

  test "noise XX handshake completes and yields cipher states" do
    a_id = Identity.generate_secp256k1()
    b_id = Identity.generate_secp256k1()

    a = Noise.new(:initiator, a_id)
    b = Noise.new(:responder, b_id)

    {m1, a} = Noise.initiator_msg1(a)
    {m2, b} = Noise.responder_msg2(b, m1)
    {m3, a, {a_out, a_in}} = Noise.initiator_msg3(a, m2)
    {b, {b_in, b_out}} = Noise.responder_finish(b, m3)

    # keys should be non-nil and paired oppositely
    assert is_binary(a_out.k) and byte_size(a_out.k) == 32
    assert is_binary(a_in.k) and byte_size(a_in.k) == 32
    assert is_binary(b_out.k) and byte_size(b_out.k) == 32
    assert is_binary(b_in.k) and byte_size(b_in.k) == 32

    assert a_out.k == b_in.k
    assert a_in.k == b_out.k

    # both sides should have recorded remote identity keys (from payload)
    assert a.remote_identity_key
    assert b.remote_identity_key
  end

  test "post-handshake transport encrypt/decrypt roundtrip" do
    a_id = Identity.generate_secp256k1()
    b_id = Identity.generate_secp256k1()

    a = Noise.new(:initiator, a_id)
    b = Noise.new(:responder, b_id)

    {m1, a} = Noise.initiator_msg1(a)
    {m2, b} = Noise.responder_msg2(b, m1)
    {m3, _a, {a_out, a_in}} = Noise.initiator_msg3(a, m2)
    {_b, {b_in, b_out}} = Noise.responder_finish(b, m3)

    msg = "hello-over-noise"

    {ct, a_out2} = Noise.transport_encrypt(a_out, msg)
    {pt, b_in2} = Noise.transport_decrypt(b_in, ct)
    assert pt == msg

    # opposite direction
    {ct2, b_out2} = Noise.transport_encrypt(b_out, "pong")
    {pt2, a_in2} = Noise.transport_decrypt(a_in, ct2)
    assert pt2 == "pong"

    assert a_out2.n == a_out.n + 1
    assert b_in2.n == b_in.n + 1
    assert b_out2.n == b_out.n + 1
    assert a_in2.n == a_in.n + 1
  end
end
