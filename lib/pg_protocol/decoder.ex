defmodule PgProtocol.Decoder do
  @moduledoc """
  Stateful decoder that accepts `iodata` packets from some postgresql server
  and decodes them into a message struct.

  Decoders come in two varieties: `frontend` and `backend`.

  A frontend decoder accepts messages from clients (e.g. `psql`) and a backend
  decoder handles those from the server.

  This matches the nomenclature of the [postgresql
  documentation](https://www.postgresql.org/docs/current/protocol-message-formats.html).

  The differing contexts are required in order to differentiate messages with
  nearly identical encoding but differing meanings for the front- and backend,
  e.g. the message tag `"D"` means a `DataRow` message when coming from the
  server and `Describe` when coming from the frontend.

  # Examples

      # create a frontend message decoder:
      decoder = PgProtocol.Decoder.frontend()

      # create a backend message decoder:
      decoder = PgProtocol.Decoder.backend()

  """
  alias PgProtocol.Message, as: M
  alias PgProtocol.Message.Error

  require Logger

  import PgProtocol.BinaryUtils

  @msg_types [
    "1",
    "2",
    "3",
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "K",
    "N",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "V",
    "W",
    "X",
    "Z",
    "c",
    "d",
    "f",
    "n",
    "p",
    "s",
    "t",
    "v"
  ]

  defstruct buffer: "", source: nil

  @type source() :: :frontend | :backend
  @type result() :: {:ok, t(), [M.t()]}

  @opaque t() :: %__MODULE__{buffer: binary(), source: source()}

  @doc """
  Create a decoder for messages coming from the client (frontend).
  """
  @spec frontend() :: t()
  def frontend() do
    new(:frontend)
  end

  @doc """
  Create a decoder for messages coming from the server (backend).
  """
  @spec backend() :: t()
  def backend() do
    new(:backend)
  end

  @doc """
  Create a decoder for the given message source (`:frontend` or `:backend`)
  """
  @spec new(source()) :: t()
  def new(source) when source in [:backend, :frontend] do
    %__MODULE__{source: source}
  end

  @doc """
  Decode the given `iodata` into a list of messages. 

  In a client-server context, any given encoded message may be split
  arbitrarily between multiple TCP packets.

  For this reason the decoder is stateful and repeated calls with sequential
  data packets must use the updated decoder or it will error.
  """
  @spec decode(t(), iodata()) :: result()
  def decode(%__MODULE__{buffer: buffer, source: source} = state, data) do
    [buffer | data]
    |> IO.iodata_to_binary()
    |> do_decode(source, [])
    |> update_state(state)
  end

  defp update_state({msgs, buffer}, state) do
    {:ok, %{state | buffer: buffer}, msgs}
  end

  defp do_decode(<<>>, _source, acc) do
    {Enum.reverse(acc), <<>>}
  end

  defp do_decode(
         <<16::i32(), 1234::i16(), 5678::i16(), pid::i32(), key::i32(), rest::binary>>,
         :frontend,
         acc
       ) do
    do_decode(rest, :frontend, [%M.CancelRequest{pid: pid, key: key} | acc])
  end

  defp do_decode(<<8::i32(), 1234::i16(), 5679::i16(), rest::binary>>, :frontend, acc) do
    do_decode(rest, :frontend, [%M.SSLRequest{} | acc])
  end

  defp do_decode(<<8::i32(), 1234::i16(), 5680::i16(), rest::binary>>, :frontend, acc) do
    do_decode(rest, :frontend, [%M.GSSENCRequest{} | acc])
  end

  defp do_decode(<<l::i32(), 3::i16(), 0::i16(), params::binary>> = m, :frontend, acc) do
    case params do
      <<p::binary-size(l - 8), rest::binary>> ->
        params = decode_key_value(p, %{})
        do_decode(rest, :frontend, [%M.StartupMessage{params: params} | acc])

      _incomplete ->
        {Enum.reverse(acc), m}
    end
  end

  defp do_decode(<<t::binary-1, s::i32(), payload::binary>> = m, source, acc)
       when t in @msg_types do
    case payload do
      <<body::binary-size(s - 4), rest::binary>> ->
        do_decode(rest, source, [decode_msg(body, t, source) | acc])

      _rest ->
        {Enum.reverse(acc), m}
    end
  end

  defp do_decode(data, _source, acc) do
    {Enum.reverse(acc), data}
  end

  def decode_msg(<<>>, "X", :frontend) do
    %M.Terminate{}
  end

  def decode_msg(query, "Q", :frontend) do
    %M.Query{query: decode_string(query)}
  end

  def decode_msg(data, "p", :frontend) do
    %M.GSSResponse{data: data}
  end

  # TODO: this and GSSResponse are impossible to tell apart without context
  #       I hope I'm never going to need to do that, in that SASL auth
  #       will only be used between this proxy and the upstream db, not between
  #       apps and the proxy.
  # def decode_msg("p", payload, :frontend) do
  #   [name, <<response_len::i32(), rest::binary>>] = split_string(payload)
  #
  #   response =
  #     if response_len > 0 do
  #       rest
  #     else
  #       nil
  #     end
  #
  #   %M.SASLInitialResponse{name: name, response: response}
  # end

  def decode_msg(<<0::i32()>>, "R", :backend) do
    %M.AuthenticationOk{}
  end

  def decode_msg(<<2::i32()>>, "R", :backend) do
    %M.AuthenticationKerberosV5{}
  end

  def decode_msg(<<3::i32()>>, "R", :backend) do
    %M.AuthenticationCleartextPassword{}
  end

  def decode_msg(<<5::i32(), salt::binary-4>>, "R", :backend) do
    %M.AuthenticationMD5Password{salt: salt}
  end

  def decode_msg(<<6::i32()>>, "R", :backend) do
    %M.AuthenticationSCMCredential{}
  end

  def decode_msg(<<7::i32()>>, "R", :backend) do
    %M.AuthenticationGSS{}
  end

  def decode_msg(<<8::i32(), data::binary>>, "R", :backend) do
    %M.AuthenticationGSSContinue{auth_data: data}
  end

  def decode_msg(<<9::i32()>>, "R", :backend) do
    %M.AuthenticationSSPI{}
  end

  def decode_msg(<<10::i32(), strs::binary>>, "R", :backend) do
    mechanisms = decode_string_list(strs, [])
    %M.AuthenticationSASL{mechanisms: mechanisms}
  end

  def decode_msg(<<11::i32(), data::binary>>, "R", :backend) do
    %M.AuthenticationSASLContinue{data: data}
  end

  def decode_msg(<<12::i32(), data::binary>>, "R", :backend) do
    %M.AuthenticationSASLFinal{data: data}
  end

  def decode_msg(<<pid::i32(), payload::binary>>, "A", :backend) do
    [channel, rest] = split_string(payload)
    [payload, ""] = split_string(rest)
    %M.NotificationResponse{pid: pid, channel: channel, payload: payload}
  end

  def decode_msg(errors, "E", :backend) do
    struct(M.ErrorResponse, Error.decode(errors))
  end

  def decode_msg(data, "E", :frontend) do
    [portal, <<max_rows::i32()>>] = split_string(data)
    %M.Execute{portal: portal, max_rows: max_rows}
  end

  def decode_msg(<<>>, "S", :frontend) do
    %M.Sync{}
  end

  def decode_msg(payload, "S", :backend) do
    [name, rest] = split_string(payload)
    [value, <<>>] = split_string(rest)
    %M.ParameterStatus{name: name, value: value}
  end

  def decode_msg(<<>>, "s", :backend) do
    %M.PortalSuspended{}
  end

  def decode_msg(<<>>, "I", :backend) do
    %M.EmptyQueryResponse{}
  end

  def decode_msg(<<pid::i32(), key::i32()>>, "K", :backend) do
    %M.BackendKeyData{pid: pid, key: key}
  end

  def decode_msg(<<s::binary-1>>, "Z", :backend) do
    status =
      case s do
        "I" -> :idle
        "T" -> :tx
        "E" -> :failed
      end

    %M.ReadyForQuery{status: status}
  end

  def decode_msg(<<t::binary-1, s::binary>>, "C", :frontend) do
    %M.Close{type: t, name: decode_string(s)}
  end

  def decode_msg(s, "C", :backend) do
    %M.CommandComplete{tag: decode_string(s)}
  end

  def decode_msg(<<_n::i16(), field_data::binary>>, "T", :backend) do
    fields = parse_row_description(field_data, [])
    %M.RowDescription{fields: fields}
  end

  def decode_msg(<<n::i16(), data::binary>>, "D", :backend) do
    {<<>>, fields} = decode_value_list(data, n, [])
    %M.DataRow{fields: fields}
  end

  def decode_msg(<<t::binary-1, rest::binary>>, "D", :frontend) do
    [name, <<>>] = split_string(rest)
    %M.Describe{name: name, type: t}
  end

  def decode_msg(data, "d", _frontend_or_backend) do
    %M.CopyData{bytes: data}
  end

  def decode_msg(<<>>, "c", _frontend_or_backend) do
    %M.CopyDone{}
  end

  def decode_msg(message, "f", :frontend) do
    %M.CopyFail{message: decode_string(message)}
  end

  def decode_msg(<<obj_id::i32(), naf::i16(), payload::binary>>, "F", :frontend) do
    {<<n::i16(), rest::binary>>, arg_format_codes} = copy_response_format(payload, naf, [])
    {<<fc::i16()>>, args} = decode_value_list(rest, n, [])

    %M.FunctionCall{
      object_id: obj_id,
      arg_format_codes: arg_format_codes,
      args: args,
      format: text_or_binary(fc)
    }
  end

  def decode_msg(data, "G", :backend) do
    struct(M.CopyInResponse, copy_response(data))
  end

  def decode_msg(data, "H", :backend) do
    struct(M.CopyOutResponse, copy_response(data))
  end

  def decode_msg(data, "W", :backend) do
    struct(M.CopyBothResponse, copy_response(data))
  end

  def decode_msg(<<l::i32(), payload::binary>>, "V", :backend) do
    result =
      if l == -1 do
        nil
      else
        binary_part(payload, 0, l)
      end

    %M.FunctionCallResponse{result: result}
  end

  def decode_msg(data, "P", :frontend) do
    [name, rest] = split_string(data)
    [query, <<n::i16(), parameter_data::binary>>] = split_string(rest)
    parameters = parse_parameters(parameter_data, n, [])
    %M.Parse{name: name, query: query, params: parameters}
  end

  def decode_msg(<<n::i16(), parameter_data::binary>>, "t", :backend) do
    parameters = parse_parameters(parameter_data, n, [])
    %M.ParameterDescription{params: parameters}
  end

  def decode_msg(<<>>, "H", :frontend) do
    %M.Flush{}
  end

  def decode_msg(<<>>, "1", :backend) do
    %M.ParseComplete{}
  end

  def decode_msg(<<>>, "n", :backend) do
    %M.NoData{}
  end

  def decode_msg(data, "B", :frontend) do
    [portal, rest] = split_string(data)
    [source, <<nf::i16(), rest::binary>>] = split_string(rest)
    <<format_code_data::binary-size(nf * 2), np::i16(), rest::binary>> = rest
    format_codes = parse_format_codes(format_code_data, nf, [])

    {<<nr::i16(), rest::binary>>, parameter_values} = decode_value_list(rest, np, [])

    <<result_format_data::binary-size(nr * 2)>> = rest
    result_format_codes = parse_format_codes(result_format_data, nr, [])

    %M.Bind{
      portal: portal,
      source: source,
      parameter_format_codes: format_codes,
      parameters: parameter_values,
      result_format_codes: result_format_codes
    }
  end

  def decode_msg(<<>>, "2", :backend) do
    %M.BindComplete{}
  end

  def decode_msg(<<>>, "3", :backend) do
    %M.CloseComplete{}
  end

  def decode_msg(body, "N", :backend) do
    struct(M.NoticeResponse, Error.decode(body))
  end

  def decode_msg(body, t, side) do
    raise RuntimeError, message: "Unrecognised #{side} message #{t}: #{inspect(body)}"
  end

  defp copy_response(<<f::i8(), n::i16(), codes::binary>>) do
    {"", format_codes} = copy_response_format(codes, n, [])

    [
      format: text_or_binary(f),
      format_codes: format_codes
    ]
  end

  defp copy_response_format(rest, 0, acc) do
    {rest, Enum.reverse(acc)}
  end

  defp copy_response_format(<<f::i16(), rest::binary>>, n, acc) do
    copy_response_format(rest, n - 1, [f | acc])
  end

  defp text_or_binary(0), do: :text
  defp text_or_binary(1), do: :binary

  defp decode_string_list(<<>>, acc) do
    Enum.reverse(acc)
  end

  defp decode_string_list(<<0>>, acc) do
    Enum.reverse(acc)
  end

  defp decode_string_list(strs, acc) do
    [m, <<rest::binary>>] = split_string(strs)
    decode_string_list(rest, [m | acc])
  end

  defp decode_value_list(rest, 0, acc) do
    {rest, Enum.reverse(acc)}
  end

  defp decode_value_list(<<-1::i32(), rest::binary>>, n, acc) do
    decode_value_list(rest, n - 1, [nil | acc])
  end

  defp decode_value_list(<<l::i32(), v::binary-size(l), rest::binary>>, n, acc) do
    decode_value_list(rest, n - 1, [v | acc])
  end

  defp parse_format_codes(<<>>, 0, acc) do
    Enum.reverse(acc)
  end

  defp parse_format_codes(<<c::i16(), rest::binary>>, n, acc) do
    parse_format_codes(rest, n - 1, [c | acc])
  end

  defp parse_parameters(<<>>, 0, acc) do
    Enum.reverse(acc)
  end

  defp parse_parameters(<<id::i32(), rest::binary>>, n, acc) do
    parse_parameters(rest, n - 1, [id | acc])
  end

  defp parse_row_description(<<>>, acc) do
    Enum.reverse(acc)
  end

  defp parse_row_description(data, acc) do
    [name, rest] = split_string(data)

    <<oid::i32(), att::i16(), type::i32(), typlen::i16(), typmod::i32(), fmt::i16(),
      rest::binary>> = rest

    parse_row_description(rest, [
      %M.RowDescription.Field{
        name: name,
        oid: oid,
        attnum: att,
        type: type,
        typlen: typlen,
        typmod: typmod,
        fmt: fmt
      }
      | acc
    ])
  end

  defp decode_key_value(<<0>>, acc) do
    acc
  end

  defp decode_key_value(p, acc) do
    [k, rest] = split_string(p)
    [v, rest] = split_string(rest)
    decode_key_value(rest, Map.put(acc, k, v))
  end

  defp decode_string(d) do
    <<s::binary-size(byte_size(d) - 1), 0>> = d
    s
  end
end
