defmodule Libp2p.Protocol do
  @moduledoc """
  Protocol ID constants for the libp2p subset we implement.

  These are string IDs negotiated via multistream-select.
  """

  @spec multistream_select() :: binary()
  def multistream_select, do: "/multistream/1.0.0"

  @spec noise() :: binary()
  def noise, do: "/noise"

  @spec yamux() :: binary()
  def yamux, do: "/yamux/1.0.0"

  @spec identify() :: binary()
  def identify, do: "/ipfs/id/1.0.0"

  @spec identify_push() :: binary()
  def identify_push, do: "/ipfs/id/push/1.0.0"

  @spec gossipsub_1_1() :: binary()
  def gossipsub_1_1, do: "/meshsub/1.1.0"
end
