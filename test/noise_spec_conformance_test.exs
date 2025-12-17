defmodule Libp2p.NoiseSpecConformanceTest do
  use ExUnit.Case, async: true

  alias Libp2p.{Identity, Noise}

  @protocol_name "Noise_XX_25519_ChaChaPoly_SHA256"

  test "default initializes ck/h as protocol name (snow / rust-libp2p interop)" do
    id = Identity.generate_secp256k1()

    st = Noise.new(:initiator, id)
    expected = @protocol_name

    assert st.ck == expected
    # Snow mixes the (possibly empty) prologue into `h`.
    assert st.h == :crypto.hash(:sha256, expected)
  end

  test "hashed protocol-name init is available when hash_protocol_name? is true" do
    id = Identity.generate_secp256k1()

    st = Noise.new(:initiator, id, <<>>, true)

    hashed = :crypto.hash(:sha256, @protocol_name)

    assert st.ck == hashed
    # Prologue is always mixed (even if empty).
    assert st.h == :crypto.hash(:sha256, hashed)
  end

  test "hkdf2 (Noise-style) matches expected vectors" do
    ck = :binary.copy(<<0>>, 32)
    ikm = :binary.copy(<<1>>, 32)

    {t1, t2} = Noise.__hkdf2__(ck, ikm)

    assert Base.encode16(t1, case: :lower) ==
             "29cbef482b4acd04af7fb3d5e8bedbaa393040396f69e325f1029ec8f99f1ed2"

    assert Base.encode16(t2, case: :lower) ==
             "aaa9461fd53198a2b68a9db5934854ed4c90f6b5d4cbe6254a08a24ee24d9e44"
  end

  test "nonce encoding is 4 zero bytes + 64-bit counter" do
    assert Noise.__nonce12__(0, :little) == <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
    assert Noise.__nonce12__(1, :little) == <<0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0>>

    n = 0x0102030405060708

    assert Noise.__nonce12__(n, :little) == <<0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1>>
    assert Noise.__nonce12__(n, :big) == <<0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8>>
  end

  test "frame/deframe roundtrip and partial buffers" do
    msg = <<1, 2, 3, 4, 5>>
    framed = Noise.frame(msg)

    assert :more = Noise.deframe(binary_part(framed, 0, 1))
    assert :more = Noise.deframe(binary_part(framed, 0, 2))

    assert {^msg, <<>>} = Noise.deframe(framed)

    # multiple frames concatenated
    msg2 = :crypto.strong_rand_bytes(17)
    buf = Noise.frame(msg) <> Noise.frame(msg2)

    assert {^msg, rest} = Noise.deframe(buf)
    assert {^msg2, <<>>} = Noise.deframe(rest)
  end

  test "frame enforces max u16 length" do
    assert_raise ArgumentError, fn -> Noise.frame(:binary.copy(<<0>>, 65_536)) end
    assert Noise.frame(<<>>) == <<0, 0>>
    assert byte_size(Noise.frame(:binary.copy(<<0>>, 65_535))) == 2 + 65_535
  end
end
