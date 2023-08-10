<a href="https://electric-sql.com">
  <picture>
    <source media="(prefers-color-scheme: dark)"
        srcset="https://raw.githubusercontent.com/electric-sql/meta/main/identity/ElectricSQL-logo-light-trans.svg"
    />
    <source media="(prefers-color-scheme: light)"
        srcset="https://raw.githubusercontent.com/electric-sql/meta/main/identity/ElectricSQL-logo-black.svg"
    />
    <img alt="ElectricSQL logo"
        src="https://raw.githubusercontent.com/electric-sql/meta/main/identity/ElectricSQL-logo-black.svg"
    />
  </picture>
</a>

[![License - Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue)](main/LICENSE)

# PgProtocol

An [Elixir](https://elixir-lang.org) library to handle the encoding and decoding of [Postgresql frontend/backend protocol](https://www.postgresql.org/docs/current/protocol.html) messages.

```elixir
# decode messages streaming from a Postgresql server over TCP
# and broadcast to GenStage consumers
defmodule PostgresConnectionProducer do
  use GenStage

  @impl GenStage
  def init(args) do
    # establish a TCP connection to the Postgresql server
    # we're ignoring any connection setup and authentication
    {:ok, conn} = :gen_tcp.connect(to_charlist(host), 5432, [active: true])

    # if we're receiving messages from a client, e.g. psql, then
    # use `PgProtocol.Decoder.frontend()`
    decoder = PgProtocol.Decoder.backend()

    {:producer, {conn, decoder}}
  end

  @impl GenStage
  def handle_info({:tcp, _conn, data}, {conn, decoder}) do
    {:ok, decoder, msgs} = PgProtocol.decode(decoder, data)
    {:noreply, msgs, {conn, decoder}}
  end
end
```

## Status

This library is used internally by [electric](https://github.com/electric-sql/electric) to de- and encode messages as part of a postgresql proxy implementation.

As such it is very much a work in progress, having only the functionality required by that project.

There are currently a few message types, `PasswordMessage`, `SASLInitialResponse` and `GSSResponse` that share a tag and are impossible to decode without some authentication flow context.

We currently only support the `GSSResponse` type and don't have any kind of context for differentiating between these messages.

## Installation

**This package is not currently published to Hex**

This package can be installed by adding `pg_protocol` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:pg_protocol, github: "electric-sql/pg_protocol"}
  ]
end
```

## License

This Elixir library is distributed under the terms of the [Apache 2.0 license](LICENSE).

## Contributing

See the [Community Guidelines](https://github.com/electric-sql/meta) including the [Guide to Contributing](https://github.com/electric-sql/meta/blob/main/CONTRIBUTING.md) and [Contributor License Agreement](https://github.com/electric-sql/meta/blob/main/CLA.md).
