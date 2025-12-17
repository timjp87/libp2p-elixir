defmodule Libp2p.NoiseNonceLimitTest do
  use ExUnit.Case, async: true

  alias Libp2p.Noise

  @u64_max 0xFFFF_FFFF_FFFF_FFFF

  test "transport encrypt/decrypt raise once nonce counter is exhausted" do
    key = :crypto.strong_rand_bytes(32)

    # last usable nonce value
    {ct, cs2} = Noise.transport_encrypt(%{k: key, n: @u64_max}, "x")
    assert is_binary(ct)
    assert cs2.n == @u64_max + 1

    assert_raise ArgumentError, ~r/nonce counter exhausted/, fn ->
      Noise.transport_encrypt(%{k: key, n: @u64_max + 1}, "x")
    end

    assert_raise ArgumentError, ~r/nonce counter exhausted/, fn ->
      Noise.transport_decrypt(%{k: key, n: @u64_max + 1}, ct)
    end
  end
end
