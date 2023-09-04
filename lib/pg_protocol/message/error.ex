defmodule PgProtocol.Message.Error do
  import PgProtocol.BinaryUtils

  require Logger

  @tags %{
    severity: "S",
    # :severity: "V",
    code: "C",
    message: "M",
    detail: "D",
    hint: "H",
    position: "P",
    internal_position: "p",
    query: "q",
    where: "W",
    schema: "s",
    table: "t",
    column: "c",
    data_type: "d",
    constraint: "n",
    file: "F",
    line: "L",
    routine: "R"
  }

  @fields Map.keys(@tags)
  @type t() :: %{
          severity: binary(),
          code: binary(),
          message: binary(),
          detail: binary(),
          hint: binary(),
          position: binary(),
          internal_position: binary(),
          query: binary(),
          where: binary(),
          schema: binary(),
          table: binary(),
          column: binary(),
          data_type: binary(),
          constraint: binary(),
          file: binary(),
          line: binary(),
          routine: binary()
        }

  def fields, do: @fields

  @spec encode(t(), binary()) :: binary()
  def encode(msg, tag) do
    payload =
      Enum.map(@tags, fn {n, t} ->
        case Map.get(msg, n, nil) do
          nil -> ""
          v -> string(<<t::binary, v::binary>>)
        end
      end)
      |> IO.iodata_to_binary()
      |> string()

    <<tag::binary, mlen(payload)::i32(), payload::binary>>
  end

  @spec decode(binary()) :: Keyword.t()
  def decode(binary) do
    decode(binary, [])
  end

  defp decode(<<0>>, acc) do
    acc
  end

  for {field, tag} <- @tags do
    defp decode(<<unquote(tag), rest::binary>>, acc) do
      [value, rest] = split_string(rest)
      decode(rest, [{unquote(field), value} | acc])
    end
  end

  # "V" is the non-localised version of the severity - rather than have
  # two values for severity, I'm just dropping it
  defp decode(<<"V", rest::binary>>, acc) do
    [_msg, rest] = split_string(rest)
    decode(rest, acc)
  end

  defp decode(<<t::binary-1, rest::binary>>, acc) do
    [msg, rest] = split_string(rest)
    Logger.warning("Dropping error field of type #{inspect(t)}: #{inspect(msg)}")
    decode(rest, acc)
  end
end
