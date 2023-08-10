defmodule PgProtocol.MessageTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias PgProtocol.{
    Encoder,
    Decoder,
    MessageGenerator
  }

  def decode(encoded, decoder) do
    Decoder.decode(decoder, encoded)
  end

  test "all types" do
    for m <- MessageGenerator.types() do
      msg = m |> MessageGenerator.generate() |> Enum.take(1) |> hd()

      for source <- m.source() do
        decoder = Decoder.new(source)
        assert {:ok, _decoder, [^msg]} = msg |> Encoder.encode() |> decode(decoder)
      end
    end
  end

  property "message round trip" do
    check all({source, m} <- MessageGenerator.message()) do
      decoder = Decoder.new(source)
      assert {:ok, _decoder, [^m]} = m |> Encoder.encode() |> decode(decoder)
    end
  end
end
