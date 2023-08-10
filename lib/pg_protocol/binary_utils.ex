defmodule PgProtocol.BinaryUtils do
  defmacro i32 do
    quote do: integer - signed - big - 32
  end

  defmacro i16 do
    quote do: integer - signed - big - 16
  end

  defmacro i8 do
    quote do: integer - signed - big - 8
  end

  defmacro u32 do
    quote do: integer - unsigned - big - 32
  end

  @doc """
  Returns the message length which is the length of the payload plus the length
  of the encoded size itself (int32 or 4 bytes)
  """
  @spec mlen(binary()) :: pos_integer()
  def mlen(m) when is_binary(m) do
    byte_size(m) + 4
  end

  @doc """
  Turns the string `s` into a zero-terminated string suitable for the pg protocol
  """
  @spec string(binary() | term()) :: binary()
  def string(s) when is_binary(s) do
    <<s::binary, 0>>
  end

  def string(term) do
    term
    |> to_string()
    |> string()
  end

  @doc """
  Splits the given binary at the first null-byte.
  """
  @spec split_string(binary) :: [binary()]
  def split_string(d) do
    :binary.split(d, <<0>>)
  end
end
