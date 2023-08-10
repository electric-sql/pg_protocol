defmodule PgProtocol.DecoderTest do
  use ExUnit.Case, async: true

  alias PgProtocol.{
    Decoder,
    Encoder,
    MessageGenerator
  }

  @length 256

  test "backend message flow" do
    messages = MessageGenerator.backend_message() |> Enum.take(@length)
    decoder = Decoder.backend()

    assert_message_decoding(messages, decoder)
  end

  test "frontend message flow" do
    messages = MessageGenerator.frontend_message() |> Enum.take(@length)
    decoder = Decoder.frontend()

    assert_message_decoding(messages, decoder)
  end

  defp assert_message_decoding(messages, decoder) do
    binary = messages |> Enum.map(&Encoder.encode/1) |> IO.iodata_to_binary()
    chunks = random_chunks(binary)

    assert IO.iodata_to_binary(chunks) == binary

    {decoded, _decoder} =
      Enum.flat_map_reduce(chunks, decoder, fn chunk, decoder ->
        {:ok, decoder, msgs} = Decoder.decode(decoder, chunk)
        {msgs, decoder}
      end)

    assert decoded == messages
  end

  def random_chunks(binary) do
    Stream.repeatedly(fn -> :rand.uniform(1024) end)
    |> Enum.reduce_while({binary, []}, fn n, {b, m} ->
      l = min(n, byte_size(b))

      case b do
        <<c::binary-size(l)>> -> {:halt, Enum.reverse([c | m])}
        <<c::binary-size(l), rest::binary>> -> {:cont, {rest, [c | m]}}
      end
    end)
  end
end
