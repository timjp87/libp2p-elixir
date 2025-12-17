defmodule Libp2p.NoiseHandshakeMatrixTest do
  use ExUnit.Case, async: true

  alias Libp2p.{Identity, Noise}

  defp do_handshake(a, b) do
    {m1, a} = Noise.initiator_msg1(a)
    {m2, b} = Noise.responder_msg2(b, m1)
    {m3, a, {_a_out, _a_in}} = Noise.initiator_msg3(a, m2)
    {_b, {_b_in, _b_out}} = Noise.responder_finish(b, m3)
    {:ok, a, b}
  rescue
    e -> {:error, e}
  end

  defp new_pair(a_cfg, b_cfg) do
    a_id = Identity.generate_secp256k1()
    b_id = Identity.generate_secp256k1()

    {a_hash?, a_hkdf_swap?, a_nonce_be?} = a_cfg
    {b_hash?, b_hkdf_swap?, b_nonce_be?} = b_cfg

    a = Noise.new(:initiator, a_id, <<>>, a_hash?, a_hkdf_swap?, a_nonce_be?)
    b = Noise.new(:responder, b_id, <<>>, b_hash?, b_hkdf_swap?, b_nonce_be?)

    {a, b}
  end

  test "handshake succeeds when both sides use the same config (including non-spec)" do
    configs =
      for hash? <- [false, true], hkdf_swap? <- [false, true], nonce_be? <- [false, true] do
        {hash?, hkdf_swap?, nonce_be?}
      end

    Enum.each(configs, fn cfg ->
      {a, b} = new_pair(cfg, cfg)
      assert match?({:ok, _a, _b}, do_handshake(a, b)), "expected handshake ok for cfg=#{inspect(cfg)}"
    end)
  end

  test "handshake fails when protocol-name hash init differs" do
    {a, b} = new_pair({true, false, false}, {false, false, false})
    assert match?({:error, %ArgumentError{}}, do_handshake(a, b))
  end

  test "handshake fails when hkdf ordering differs" do
    {a, b} = new_pair({true, false, false}, {true, true, false})
    assert match?({:error, %ArgumentError{}}, do_handshake(a, b))
  end

  test "handshake fails when handshake nonce endianness differs" do
    {a, b} = new_pair({true, false, false}, {true, false, true})
    assert match?({:error, %ArgumentError{}}, do_handshake(a, b))
  end

  test "defaults are spec-compatible and complete a handshake" do
    a_id = Identity.generate_secp256k1()
    b_id = Identity.generate_secp256k1()

    a = Noise.new(:initiator, a_id)
    b = Noise.new(:responder, b_id)

    assert match?({:ok, _a, _b}, do_handshake(a, b))
  end
end
