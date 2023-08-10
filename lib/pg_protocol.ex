defmodule PgProtocol do
  @moduledoc """
  """
  @type message() :: PgProtocol.Message.t() | [PgProtocol.Message.t()]

  @doc """
  Encode a message (or list of messages) into binary.
  """
  @spec encode(message()) :: binary()
  def encode(msg) do
    PgProtocol.Encoder.encode(msg)
  end

  @doc """
  Decode `iodata()` into a list of messages. 

  This is meant to be used within some kind of `GenServer` since the decoder
  must maintain state between calls in order to handle messages split across
  multiple TCP packets.

  # Example

      decoder = PgProtocol.Decoder.backend()

      {:ok, decoder, msgs} = PgProtocol.decode(decoder, iodata)

  """
  @spec decode(PgProtocol.Decoder.t(), iodata()) :: PgProtocol.Decoder.result()
  def decode(decoder, data) do
    PgProtocol.Decoder.decode(decoder, data)
  end
end
