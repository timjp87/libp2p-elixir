defmodule Libp2p.MultistreamSelectTest do
  use ExUnit.Case, async: true

  alias Libp2p.MultistreamSelect, as: MSS

  test "initiator/responder negotiate a common protocol" do
    init = MSS.new_initiator(["/noise", "/tls/1.0.0"])
    resp = MSS.new_responder()

    supported = MapSet.new(["/noise", "/yamux/1.0.0"])

    {out_i0, init} = MSS.start(init)
    {out_r0, resp} = MSS.start(resp)

    # exchange multistream headers
    {ev_r1, out_r1, resp} = MSS.feed(resp, out_i0, supported)
    assert ev_r1 == []
    assert out_r1 == <<>>

    {ev_i1, out_i1, init} = MSS.feed(init, out_r0, MapSet.new())
    assert ev_i1 == []
    assert out_i1 != <<>> # initiator sends proposal after seeing responder mss

    # responder receives proposal and echoes supported protocol
    {ev_r2, out_r2, _resp} = MSS.feed(resp, out_i1, supported)
    assert {:selected, "/noise"} in ev_r2
    assert out_r2 != <<>>

    {ev_i2, _out_i2, init} = MSS.feed(init, out_r2, MapSet.new())
    assert {:selected, "/noise"} in ev_i2
    assert init.selected == "/noise"
  end
end
