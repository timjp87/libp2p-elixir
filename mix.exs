defmodule Libp2p.MixProject do
  use Mix.Project

  def project do
    [
      app: :libp2p_elixir,
      version: "0.1.0",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # kept intentionally minimal; avoid pulling in full protobuf stacks
    ]
  end
end
