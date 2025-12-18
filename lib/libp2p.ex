defmodule Libp2p do
  @moduledoc """
  An Elixir implementation of the Libp2p networking stack.

  This library provides the core components required to participate in a peer-to-peer network
  compatible with the standard Libp2p specifications.

  ## Features

  - **Transport**: TCP transport implementation (`Libp2p.Transport.Tcp`).
  - **Security**: Noise secure channel handshake (Noise_XX_25519_ChaChaPoly_SHA256).
    See `Libp2p.Noise`.
  - **Multiplexing**: Yamux v1.0.0 stream multiplexing. See `Libp2p.Yamux.Session`.
  - **PubSub**: Gossipsub v1.1 protocol for efficient message propagation.
    See `Libp2p.Gossipsub`.
  - **Peer Identity**: ED25519 and Secp256k1 key support for peer identities.
  - **Protocol Negotiation**: Multistream-select 1.0 support.

  ## Architecture

  The library follows a process-per-connection model:

  - `Libp2p.Swarm`: The central manager that handles listening sockets and outbound dialing.
    It spawns a connection process for each established peer.
  - `Libp2p.ConnectionV2`: Represents a single physical peer connection. It is responsible for
    the full lifecycle: upgrading the raw socket to a secure channel, negotiating a multiplexer,
    and managing concurrent logical streams.
  - `Libp2p.InboundStream`: A behaviour for defining handlers for specific protocols (e.g.,
    `/ipfs/id/1.0.0` or custom application protocols).

  ## Usage

  To start the stack, add `Libp2p.Supervisor` to your supervision tree and configure the
  identity and initial listen addresses.
  """
end
