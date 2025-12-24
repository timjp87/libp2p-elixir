# Libp2p Elixir

An Elixir implementation of the Libp2p networking stack.

## Features

- **Transport**: TCP
- **Secure Channel**: Noise (`Noise_XX_25519_ChaChaPoly_SHA256`)
- **Multiplexing**: Yamux v1.0.0
- **PubSub**: Gossipsub v1.1
- **Discovery**: Identify, Identify Push

## Installation

Add `libp2p_elixir` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:libp2p_elixir, "~> 0.9.3"}
  ]
end
```

## Minimal Usage Example

### 1. Define a Protocol Handler

Implement a module with `handle_inbound/3` to handle incoming streams for your custom protocol.

```elixir
defmodule MyApp.EchoHandler do
  require Logger

  # Handle incoming streams for protocol "/echo/1.0.0"
  def handle_inbound(conn, stream_id, _initial_data) do
    Logger.info("New echo stream opened: StreamID #{stream_id}")
    # Take ownership of the stream to receive messages
    Libp2p.ConnectionV2.set_stream_handler(conn, stream_id, self())
    loop(conn, stream_id)
  end

  defp loop(conn, stream_id) do
    receive do
      {:libp2p, :stream_data, ^conn, ^stream_id, data} ->
        # Echo the data back
        Libp2p.ConnectionV2.send_stream(conn, stream_id, data)
        loop(conn, stream_id)

      {:libp2p, :stream_closed, ^conn, ^stream_id} ->
        Logger.info("Stream closed")
    end
  end
end
```

### 2. Configure the Supervisor

Add `Libp2p.Supervisor` to your application's supervision tree. You need to provide a peer identity.

```elixir
# In lib/my_app/application.ex
def start(_type, _args) do
  # Generate or load a persistent identity
  identity = Libp2p.Identity.new() 

  children = [
    {Libp2p.Supervisor, [
      identity: identity,
      # Register your protocol handlers
      protocol_handlers: %{
        "/echo/1.0.0" => MyApp.EchoHandler
      }
    ]}
  ]

  opts = [strategy: :one_for_one, name: MyApp.Supervisor]
  Supervisor.start_link(children, opts)
end
```

### 3. Start Listening

After the supervisor is started, tell the Swarm to listen on a port.

```elixir
# You might do this in a Task or handle_continue in your application
Libp2p.Swarm.listen(Libp2p.Swarm, {0, 0, 0, 0}, 9000)
```

### 4. Dialing a Peer

You can use the swarm to dial other peers.

```elixir
# Takes an IP tuple and a port
{:ok, conn_pid} = Libp2p.Swarm.dial(Libp2p.Swarm, {127, 0, 0, 1}, 9001)

# Open a new stream on the connection
{:ok, stream_id} = Libp2p.ConnectionV2.open_stream(conn_pid)

# Negotiate the protocol
{:ok, "/echo/1.0.0", _} = Libp2p.StreamNegotiator.negotiate_outbound(
  conn_pid,
  stream_id,
  ["/echo/1.0.0"],
  MapSet.new(["/echo/1.0.0"]) # Supported protocols
)

# Send data
Libp2p.ConnectionV2.send_stream(conn_pid, stream_id, "Hello Libp2p!")
```
