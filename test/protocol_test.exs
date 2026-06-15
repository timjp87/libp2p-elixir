defmodule Libp2p.ProtocolTest do
  use ExUnit.Case, async: true

  alias Libp2p.Protocol

  test "gossipsub protocol ids include supported meshsub versions" do
    assert Protocol.gossipsub_1_2() == "/meshsub/1.2.0"
    assert Protocol.gossipsub_1_1() == "/meshsub/1.1.0"
    assert Protocol.gossipsub_1_0() == "/meshsub/1.0.0"
  end
end
