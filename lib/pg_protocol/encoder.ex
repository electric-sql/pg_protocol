defprotocol PgProtocol.Encoder do
  @spec encode(t()) :: binary()
  def encode(m)
end

defimpl PgProtocol.Encoder, for: List do
  def encode(list) do
    list
    |> Enum.map(&PgProtocol.Encoder.encode/1)
    |> IO.iodata_to_binary()
  end
end

defimpl PgProtocol.Encoder, for: BitString do
  def encode(binary), do: binary
end
