defmodule Libp2p.MixProject do
  use Mix.Project

  def project do
    [
      app: :libp2p_elixir,
      version: "0.9.3",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
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
      # Documentation
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end

  defp description do
    "A standalone Elixir implementation of the Libp2p networking stack"
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/timjp87/libp2p-elixir"}
    ]
  end
end
