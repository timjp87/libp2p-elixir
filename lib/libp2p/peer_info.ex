defmodule Libp2p.PeerInfo do
  @moduledoc """
  Peer metadata tracked by `Libp2p.PeerStore`.
  """

  alias Libp2p.Multiaddr

  @type t :: %__MODULE__{
          peer_id: binary(),
          addrs: [Multiaddr.t()],
          protocols: MapSet.t(binary()),
          agent_version: binary() | nil,
          protocol_version: binary() | nil,
          observed_addr: Multiaddr.t() | nil,
          last_seen_ms: non_neg_integer() | nil
        }

  defstruct [
    :peer_id,
    addrs: [],
    protocols: MapSet.new(),
    agent_version: nil,
    protocol_version: nil,
    observed_addr: nil,
    last_seen_ms: nil
  ]
end
