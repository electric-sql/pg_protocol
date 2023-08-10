defmodule PgProtocolTest do
  use ExUnit.Case

  alias PgProtocol.MessageGenerator

  test "encode/decode frontend" do
    msgs = MessageGenerator.frontend_message() |> Enum.take(8)
    decoder = PgProtocol.Decoder.frontend()

    binary = PgProtocol.encode(msgs)
    assert {:ok, _decoder, ^msgs} = PgProtocol.decode(decoder, binary)
  end

  test "encode/decode backend" do
    msgs = MessageGenerator.backend_message() |> Enum.take(8)
    decoder = PgProtocol.Decoder.backend()

    binary = PgProtocol.encode(msgs)
    assert {:ok, _decoder, ^msgs} = PgProtocol.decode(decoder, binary)
  end
end
