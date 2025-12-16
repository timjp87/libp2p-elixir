defmodule Libp2p.PubsubRpcTest do
  use ExUnit.Case, async: true

  alias Libp2p.Pubsub

  test "encode/decode RPC with strictnosign message" do
    msg = Pubsub.build_strict_no_sign_message("topicA", "data")
    :ok = Pubsub.validate_strict_no_sign!(msg)

    rpc = %{subscriptions: [%{subscribe: true, topicid: "topicA"}], publish: [msg]}
    bin = Pubsub.encode_rpc(rpc)
    out = Pubsub.decode_rpc(bin)

    assert out.subscriptions == [%{subscribe: true, topicid: "topicA"}]
    assert length(out.publish) == 1
    assert hd(out.publish).topic == "topicA"
    assert hd(out.publish).data == "data"
    :ok = Pubsub.validate_strict_no_sign!(hd(out.publish))
  end

  test "strictnosign rejects presence of signature fields" do
    msg = %{topic: "t", data: "d", signature: "sig"}
    assert_raise ArgumentError, fn -> Pubsub.validate_strict_no_sign!(msg) end
  end
end
