defmodule Libp2p.YamuxTest do
  use ExUnit.Case, async: true

  alias Libp2p.Yamux.{Frame, Session}

  test "frame encode/decode roundtrip (data)" do
    f = %Frame{type: :data, flags: 0x1, stream_id: 7, data: "abc"}
    bin = Frame.encode(f) |> IO.iodata_to_binary()
    {f2, rest} = Frame.decode_one(bin)
    assert rest == <<>>
    assert f2.type == :data
    assert f2.flags == 0x1
    assert f2.stream_id == 7
    assert f2.data == "abc"
  end

  test "session open/ack/data (loopback)" do
    a = Session.new(:client)
    b = Session.new(:server)

    {sid, out_a1, a} = Session.open_stream(a)
    assert rem(sid, 2) == 1

    {events_b1, out_b1, b} = Session.feed(b, out_a1)
    assert {:stream_open, sid} in events_b1
    assert out_b1 != <<>> # ACK

    {_events_a1, _out_a1b, a} = Session.feed(a, out_b1)

    {out_a2, _a} = Session.send_data(a, sid, "hello")
    {events_b2, _out_b2, _b} = Session.feed(b, out_a2)
    assert {:stream_data, sid, "hello"} in events_b2
  end
end

