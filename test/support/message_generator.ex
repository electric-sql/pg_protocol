defmodule PgProtocol.MessageGenerator do
  alias PgProtocol.Message, as: M
  import StreamData

  @after_compile __MODULE__

  # validate that the generator supports all the message types
  def __after_compile__(env, _bytecode) do
    for m <- M.types() do
      try do
        env.module.generate(m)
      rescue
        FunctionClauseError ->
          raise "#{__MODULE__} does not support message type #{m}"
      end
    end
  end

  # SASLInitialResponse, PasswordMessage and GSSResponse share the same message format
  # specifier, "p" so it's awkward to tell them apart without maintaining
  # context/auth state which we don't need apart from to support this one
  # message type
  #
  # Since we won't enable SASL auth between the proxy and the frontend,
  # decoding SASLInitialResponse won't be required, only encoding.
  @undecoded_types [M.SASLInitialResponse, M.SASLResponse, M.PasswordMessage]
  @types M.types() |> Enum.reject(&(&1 in @undecoded_types))

  @backend_types Enum.filter(@types, &(:backend in &1.source()))
  @frontend_types Enum.filter(@types, &(:frontend in &1.source()))

  def types, do: @types

  def message_type do
    member_of(@types)
  end

  def frontend_message_type do
    member_of(@frontend_types)
  end

  def backend_message_type do
    member_of(@backend_types)
  end

  def frontend_message do
    frontend_message_type()
    |> message_generator()
    |> map(fn {_, m} -> m end)
  end

  def backend_message do
    backend_message_type()
    |> message_generator()
    |> map(fn {_, m} -> m end)
  end

  def message do
    message_generator(message_type())
  end

  defp message_generator(type) do
    bind(type, fn m ->
      tuple({member_of(m.source()), generate(m)})
    end)
  end

  defp mstruct(module, fields) do
    fields
    |> fixed_map()
    |> map(&struct(module, &1))
  end

  defp copy_response(m) do
    bind(member_of([:text, :binary]), fn format ->
      format_code =
        case format do
          :text -> constant(0)
          :binary -> member_of([0, 1])
        end

      mstruct(m, format: constant(format), format_codes: list_of(format_code))
    end)
  end

  @constants [
    M.AuthenticationOk,
    M.AuthenticationKerberosV5,
    M.AuthenticationCleartextPassword,
    M.AuthenticationSCMCredential,
    M.AuthenticationGSS,
    M.AuthenticationSSPI,
    M.BindComplete,
    M.CloseComplete,
    M.CopyDone,
    M.EmptyQueryResponse,
    M.Flush,
    M.NoData,
    M.ParseComplete,
    M.PortalSuspended,
    M.SSLRequest,
    M.Sync,
    M.Terminate,
    M.GSSENCRequest
  ]

  for m <- @constants do
    def generate(unquote(m)) do
      constant(struct(unquote(m)))
    end
  end

  def generate(M.AuthenticationMD5Password = m) do
    mstruct(m, salt: binary(length: m.salt_length()))
  end

  def generate(M.AuthenticationGSSContinue = m) do
    mstruct(m, auth_data: binary(min_length: 4, max_length: 64))
  end

  def generate(M.AuthenticationSASL = m) do
    mstruct(m, mechanisms: list_of(string(:alphanumeric)))
  end

  def generate(M.AuthenticationSASLContinue = m) do
    mstruct(m, data: binary(min_length: 4, max_length: 128))
  end

  def generate(M.AuthenticationSASLFinal = m) do
    mstruct(m, data: binary(min_length: 4, max_length: 128))
  end

  def generate(M.BackendKeyData = m) do
    mstruct(m, pid: integer(1..65536), key: integer(1..65536))
  end

  def generate(M.Bind = m) do
    bind(integer(0..6), fn n ->
      mstruct(m,
        portal: string(:alphanumeric),
        source: string(:alphanumeric),
        parameter_format_codes: list_of(integer(), length: n),
        parameters: list_of(binary(), length: n),
        result_format_codes: list_of(integer(), length: n)
      )
    end)
  end

  def generate(M.CancelRequest = m) do
    mstruct(m, pid: integer(), key: integer())
  end

  def generate(M.Close = m) do
    mstruct(m, type: binary(length: 1), name: string(:alphanumeric))
  end

  def generate(M.CommandComplete = m) do
    mstruct(m, tag: string(:alphanumeric))
  end

  def generate(M.CopyData = m) do
    mstruct(m, bytes: binary())
  end

  def generate(M.CopyFail = m) do
    mstruct(m, message: string(:alphanumeric))
  end

  def generate(M.CopyInResponse = m) do
    copy_response(m)
  end

  def generate(M.CopyOutResponse = m) do
    copy_response(m)
  end

  def generate(M.CopyBothResponse = m) do
    copy_response(m)
  end

  def generate(M.DataRow = m) do
    mstruct(m, fields: list_of(one_of([constant(nil), binary()])))
  end

  def generate(M.Describe = m) do
    mstruct(m, type: member_of(["S", "P"]), name: string(:alphanumeric))
  end

  def generate(M.ErrorResponse = m) do
    notify_error(m)
  end

  def generate(M.Execute = m) do
    mstruct(m, portal: string(:alphanumeric), max_rows: integer(0..65536))
  end

  def generate(M.FunctionCall = m) do
    mstruct(m,
      object_id: integer(),
      arg_format_codes: list_of(member_of([0, 1])),
      args: list_of(binary()),
      format: member_of([:text, :binary])
    )
  end

  def generate(M.FunctionCallResponse = m) do
    mstruct(m,
      result: one_of([constant(nil), binary()])
    )
  end

  def generate(M.GSSResponse = m) do
    mstruct(m, data: binary())
  end

  def generate(M.NoticeResponse = m) do
    notify_error(m)
  end

  def generate(M.NotificationResponse = m) do
    mstruct(m, pid: integer(), channel: string(:alphanumeric), payload: string(:alphanumeric))
  end

  def generate(M.ParameterDescription = m) do
    mstruct(m, params: list_of(integer(), min_length: 0, max_length: 6))
  end

  def generate(M.ParameterStatus = m) do
    mstruct(m, name: string(:alphanumeric), value: string(:alphanumeric))
  end

  def generate(M.Parse = m) do
    mstruct(m,
      name: string(:alphanumeric),
      query: string(:alphanumeric),
      params: list_of(integer())
    )
  end

  def generate(M.PasswordMessage = m) do
    mstruct(m, password: string(:alphanumeric))
  end

  def generate(M.Query = m) do
    mstruct(m, query: string(:alphanumeric))
  end

  def generate(M.ReadyForQuery = m) do
    mstruct(m, status: member_of([:idle, :tx, :failed]))
  end

  def generate(M.RowDescription = m) do
    mstruct(m,
      fields:
        list_of(
          mstruct(M.RowDescription.Field,
            name: string(:alphanumeric),
            oid: integer(),
            attnum: integer(),
            type: integer(),
            typlen: integer(),
            typmod: integer(),
            fmt: integer()
          )
        )
    )
  end

  def generate(M.SASLInitialResponse = m) do
    mstruct(m, name: string(:alphanumeric), response: one_of([constant(nil), binary()]))
  end

  def generate(M.SASLResponse = m) do
    mstruct(m, data: binary())
  end

  def generate(M.StartupMessage = m) do
    mstruct(m, params: map_of(string(:alphanumeric), string(:alphanumeric)))
  end

  defp notify_error(m) do
    mstruct(m,
      severity: string(:alphanumeric),
      code: string(:alphanumeric),
      message: string(:alphanumeric),
      detail: string(:alphanumeric),
      hint: string(:alphanumeric),
      position: string(:alphanumeric),
      internal_position: string(:alphanumeric),
      query: string(:alphanumeric),
      where: string(:alphanumeric),
      schema: string(:alphanumeric),
      table: string(:alphanumeric),
      column: string(:alphanumeric),
      data_type: string(:alphanumeric),
      constraint: string(:alphanumeric),
      file: string(:alphanumeric),
      line: string(:alphanumeric),
      routine: string(:alphanumeric)
    )
  end
end
