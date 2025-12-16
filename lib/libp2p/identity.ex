defmodule Libp2p.Identity do
  @moduledoc """
  libp2p identity keys + PeerId.
  """

  alias Libp2p.Crypto.Secp256k1
  alias Libp2p.PeerId

  @type t :: %__MODULE__{
          privkey: binary(),
          pubkey_uncompressed: binary(),
          pubkey_compressed: binary(),
          peer_id: binary()
        }

  defstruct [:privkey, :pubkey_uncompressed, :pubkey_compressed, :peer_id]

  @spec generate_secp256k1() :: t()
  def generate_secp256k1 do
    {priv, pub_uncompressed} = Secp256k1.generate_keypair()
    pub_compressed = Secp256k1.compress_pubkey(pub_uncompressed)
    peer_id = PeerId.from_secp256k1_pubkey_compressed(pub_compressed)
    %__MODULE__{
      privkey: priv,
      pubkey_uncompressed: pub_uncompressed,
      pubkey_compressed: pub_compressed,
      peer_id: peer_id
    }
  end
end
