defmodule SpeckEx.MixProject do
  use Mix.Project

  def project do
    [
      app: :speck_ex,
      version: "0.0.0+development",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: """
      Speck block cipher for Elixir, backed by Rust.
      """,
      package: [
        files: [
          "lib",
          "native/speck_ex/.cargo",
          "native/speck_ex/src",
          "native/speck_ex/Cargo*",
          "native/speck_ex/Cross.toml",
          ".formatter.exs",
          "mix.exs",
          "*.md",
          "checksum-*.exs"
        ],
        licenses: ["Apache-2.0"],
        links: %{github: "https://github.com/juulSme/SpeckEx"},
        source_url: "https://github.com/juulSme/SpeckEx"
      ],
      source_url: "https://github.com/juulSme/SpeckEx",
      name: "SpeckEx",
      docs: [
        source_ref: ~s(main),
        extras: ~w(./README.md ./LICENSE.md),
        main: "SpeckEx",
        skip_undefined_reference_warnings_on: ~w()
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
      {:rustler, "0.37.1", optional: true},
      {:rustler_precompiled, "~> 0.8"},
      {:ex_doc, "~> 0.36", only: [:dev, :test], runtime: false},
      {:benchmark, github: "juulSme/benchmark_ex", only: [:dev, :test]}
    ]
  end
end
