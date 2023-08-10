defmodule PgProtocol.Message do
  alias PgProtocol.Encoder
  alias PgProtocol.Message.Error

  import PgProtocol.BinaryUtils

  Module.register_attribute(__MODULE__, :message, accumulate: true)

  @message AuthenticationOk
  defmodule AuthenticationOk do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(_m) do
        <<"R", 8::i32(), 0::i32()>>
      end
    end
  end

  @message AuthenticationKerberosV5
  defmodule AuthenticationKerberosV5 do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:backend]

    def new(_args \\ []) do
      %__MODULE__{}
    end

    defimpl Encoder do
      def encode(_m) do
        <<"R", 8::i32(), 2::i32()>>
      end
    end
  end

  @message AuthenticationCleartextPassword
  defmodule AuthenticationCleartextPassword do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:backend]

    def new(_args \\ []) do
      %__MODULE__{}
    end

    defimpl Encoder do
      def encode(_m) do
        <<"R", 8::i32(), 3::i32()>>
      end
    end
  end

  @message AuthenticationMD5Password
  defmodule AuthenticationMD5Password do
    defstruct salt: ""

    @type t() :: %__MODULE__{salt: binary()}

    @salt_length 4

    def source, do: [:backend]

    def salt_length, do: @salt_length

    def salt do
      # :crypto.strong_rand_bytes(@salt_length)
      "salt"
    end

    def new(args \\ []) do
      salt = Keyword.get_lazy(args, :salt, &salt/0)
      %__MODULE__{salt: salt}
    end

    defimpl Encoder do
      def encode(m) do
        <<"R", 12::i32(), 5::i32(), m.salt::binary>>
      end
    end
  end

  @message AuthenticationSCMCredential
  defmodule AuthenticationSCMCredential do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(_m) do
        <<"R", 8::i32(), 6::i32()>>
      end
    end
  end

  @message AuthenticationGSS
  defmodule AuthenticationGSS do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(_m) do
        <<"R", 8::i32(), 7::i32()>>
      end
    end
  end

  @message AuthenticationGSSContinue
  defmodule AuthenticationGSSContinue do
    defstruct [:auth_data]

    @type t() :: %__MODULE__{auth_data: binary()}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        payload = <<8::i32(), m.auth_data::binary>>
        <<"R", mlen(payload)::i32(), payload::binary>>
      end
    end
  end

  @message AuthenticationSSPI
  defmodule AuthenticationSSPI do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(_m) do
        <<"R", 8::i32(), 9::i32()>>
      end
    end
  end

  @message AuthenticationSASL
  defmodule AuthenticationSASL do
    defstruct [:mechanisms]

    @type t() :: %__MODULE__{mechanisms: [binary()]}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        payload =
          m.mechanisms
          |> Enum.map(&string/1)
          |> IO.iodata_to_binary()
          |> string()

        l = mlen(payload) + 4
        <<"R", l::i32(), 10::i32(), payload::binary>>
      end
    end
  end

  @message AuthenticationSASLContinue
  defmodule AuthenticationSASLContinue do
    defstruct [:data]

    @type t() :: %__MODULE__{data: binary()}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        payload = <<11::i32(), m.data::binary>>
        <<"R", mlen(payload)::i32(), payload::binary>>
      end
    end
  end

  @message AuthenticationSASLFinal
  defmodule AuthenticationSASLFinal do
    defstruct [:data]

    @type t() :: %__MODULE__{data: binary()}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        payload = <<12::i32(), m.data::binary>>
        <<"R", mlen(payload)::i32(), payload::binary>>
      end
    end
  end

  @message BackendKeyData
  defmodule BackendKeyData do
    defstruct [:pid, :key]

    @type t() :: %__MODULE__{pid: integer(), key: integer()}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        <<"K", 12::i32(), m.pid::i32(), m.key::i32()>>
      end
    end
  end

  @message Bind
  defmodule Bind do
    defstruct [:portal, :source, :parameter_format_codes, :parameters, :result_format_codes]

    @type t() :: %__MODULE__{
            portal: String.t(),
            source: String.t(),
            parameter_format_codes: [integer()],
            parameters: [nil | binary()],
            result_format_codes: [integer()]
          }

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(m) do
        format_codes =
          Enum.map(m.parameter_format_codes, &<<&1::i16()>>)
          |> IO.iodata_to_binary()

        parameters =
          Enum.map(m.parameters, fn
            nil ->
              <<-1::i32()>>

            v when is_binary(v) ->
              <<byte_size(v)::i32(), v::binary>>
          end)
          |> IO.iodata_to_binary()

        result_format_codes =
          Enum.map(m.result_format_codes, &<<&1::i16()>>) |> IO.iodata_to_binary()

        payload =
          <<string(m.portal)::binary, string(m.source)::binary,
            length(m.parameter_format_codes)::i16(), format_codes::binary,
            length(m.parameters)::i16(), parameters::binary, length(m.result_format_codes)::i16(),
            result_format_codes::binary>>

        <<"B", mlen(payload)::i32(), payload::binary>>
      end
    end
  end

  @message BindComplete
  defmodule BindComplete do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(_m) do
        <<"2", 4::i32()>>
      end
    end
  end

  @message CancelRequest
  defmodule CancelRequest do
    defstruct [:pid, :key]

    @type t() :: %__MODULE__{pid: integer(), key: integer()}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(m) do
        <<16::i32(), 1234::i16(), 5678::i16(), m.pid::i32(), m.key::i32()>>
      end
    end
  end

  @message Close
  defmodule Close do
    defstruct [:type, :name]

    @type t() :: %__MODULE__{type: binary(), name: String.t()}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(m) do
        payload = <<m.type::binary, string(m.name)::binary>>
        <<"C", mlen(payload)::i32(), payload::binary>>
      end
    end
  end

  @message CloseComplete
  defmodule CloseComplete do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(_m) do
        <<"3", 4::i32()>>
      end
    end
  end

  @message CommandComplete
  defmodule CommandComplete do
    defstruct [:tag]

    @type t() :: %__MODULE__{tag: String.t()}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        payload = string(m.tag)
        <<"C", mlen(payload)::i32(), payload::binary>>
      end
    end
  end

  @message CopyData
  defmodule CopyData do
    defstruct [:bytes]

    @type t() :: %__MODULE__{bytes: binary()}

    def source, do: [:frontend, :backend]

    defimpl Encoder do
      def encode(m) do
        <<"d", mlen(m.bytes)::i32(), m.bytes::binary>>
      end
    end
  end

  @message CopyDone
  defmodule CopyDone do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:frontend, :backend]

    defimpl Encoder do
      def encode(_m) do
        <<"c", 4::i32()>>
      end
    end
  end

  @message CopyFail
  defmodule CopyFail do
    defstruct [:message]

    @type t() :: %__MODULE__{message: String.t()}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(m) do
        payload = string(m.message)
        <<"f", mlen(payload)::i32(), payload::binary>>
      end
    end
  end

  @message CopyInResponse
  defmodule CopyInResponse do
    defstruct [:format, :format_codes]

    @type t() :: %__MODULE__{format: :text | :binary, format_codes: [integer()]}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        payload =
          [
            <<encode_format(m)::i8(), length(m.format_codes)::i16()>>
            | Enum.map(m.format_codes, &<<&1::i16()>>)
          ]
          |> IO.iodata_to_binary()

        <<"G", mlen(payload)::i32(), payload::binary>>
      end

      defp encode_format(%{format: :text}), do: 0
      defp encode_format(%{format: :binary}), do: 1
    end
  end

  @message CopyOutResponse
  defmodule CopyOutResponse do
    defstruct [:format, :format_codes]

    @type t() :: %__MODULE__{format: :text | :binary, format_codes: [integer()]}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        payload =
          [
            <<encode_format(m)::i8(), length(m.format_codes)::i16()>>
            | Enum.map(m.format_codes, &<<&1::i16()>>)
          ]
          |> IO.iodata_to_binary()

        <<"H", mlen(payload)::i32(), payload::binary>>
      end

      defp encode_format(%{format: :text}), do: 0
      defp encode_format(%{format: :binary}), do: 1
    end
  end

  @message CopyBothResponse
  defmodule CopyBothResponse do
    defstruct [:format, :format_codes]

    @type t() :: %__MODULE__{format: :text | :binary, format_codes: [integer()]}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        payload =
          [
            <<encode_format(m)::i8(), length(m.format_codes)::i16()>>
            | Enum.map(m.format_codes, &<<&1::i16()>>)
          ]
          |> IO.iodata_to_binary()

        <<"W", mlen(payload)::i32(), payload::binary>>
      end

      defp encode_format(%{format: :text}), do: 0
      defp encode_format(%{format: :binary}), do: 1
    end
  end

  @message DataRow
  defmodule DataRow do
    defstruct [:fields]

    @type t() :: %__MODULE__{fields: [nil | binary()]}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        fields =
          [
            <<length(m.fields)::i16()>>
            | Enum.map(m.fields, fn
                nil -> <<-1::i32()>>
                v -> <<byte_size(v)::i32(), v::binary>>
              end)
          ]
          |> IO.iodata_to_binary()

        <<"D", mlen(fields)::i32(), fields::binary>>
      end
    end
  end

  @message Describe
  defmodule Describe do
    defstruct [:type, :name]

    @type t() :: %__MODULE__{type: binary(), name: String.t()}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(m) do
        payload = <<m.type::binary, string(m.name)::binary>>
        <<"D", mlen(payload)::i32(), payload::binary>>
      end
    end
  end

  @message EmptyQueryResponse
  defmodule EmptyQueryResponse do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(_m) do
        <<"I", 4::i32()>>
      end
    end
  end

  @message ErrorResponse
  defmodule ErrorResponse do
    defstruct Error.fields()

    @type t() :: %__MODULE__{
            severity: String.t(),
            code: String.t(),
            message: String.t(),
            detail: String.t(),
            hint: String.t(),
            position: String.t(),
            internal_position: String.t(),
            query: String.t(),
            where: String.t(),
            schema: String.t(),
            table: String.t(),
            column: String.t(),
            data_type: String.t(),
            constraint: String.t(),
            file: String.t(),
            line: String.t(),
            routine: String.t()
          }

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        Error.encode(m, "E")
      end
    end
  end

  @message Execute
  defmodule Execute do
    defstruct [:portal, :max_rows]

    @type t() :: %__MODULE__{portal: String.t(), max_rows: integer()}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(m) do
        payload = <<string(m.portal)::binary, m.max_rows::i32()>>
        <<"E", mlen(payload)::i32(), payload::binary>>
      end
    end
  end

  @message Flush
  defmodule Flush do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(_m) do
        <<"H", 4::i32()>>
      end
    end
  end

  @message FunctionCall
  defmodule FunctionCall do
    defstruct [:object_id, :arg_format_codes, :args, :format]

    @type t() :: %__MODULE__{
            object_id: integer(),
            arg_format_codes: [integer()],
            args: [binary()],
            format: :text | :binary
          }

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(m) do
        payload =
          [
            <<m.object_id::i32(), length(m.arg_format_codes)::i16()>>,
            Enum.map(m.arg_format_codes, &<<&1::i16()>>),
            <<length(m.args)::i16()>>,
            Enum.map(m.args, &<<byte_size(&1)::i32(), &1::binary>>),
            <<encode_format(m)::i16()>>
          ]
          |> IO.iodata_to_binary()

        <<"F", mlen(payload)::i32(), payload::binary>>
      end

      defp encode_format(%{format: :text}), do: 0
      defp encode_format(%{format: :binary}), do: 1
    end
  end

  @message FunctionCallResponse
  defmodule FunctionCallResponse do
    defstruct [:result]

    @type t() :: %__MODULE__{
            result: nil | binary()
          }

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        payload =
          if is_nil(m.result) do
            <<-1::i32()>>
          else
            <<byte_size(m.result)::i32(), m.result::binary>>
          end

        <<"V", mlen(payload)::i32(), payload::binary>>
      end
    end
  end

  @message GSSENCRequest
  defmodule GSSENCRequest do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(_m) do
        <<8::i32(), 1234::i16(), 5680::i16()>>
      end
    end
  end

  @message GSSResponse
  defmodule GSSResponse do
    @moduledoc """
    A GSSAPI or SSPI response. Note that this is also used for SASL and
    password response messages. The exact message type can be deduced from the
    context.
    """

    defstruct [:data]

    @type t() :: %__MODULE__{data: binary()}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(m) do
        <<"p", mlen(m.data)::i32(), m.data::binary>>
      end
    end
  end

  @message NoData
  defmodule NoData do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(_m) do
        <<"n", 4::i32()>>
      end
    end
  end

  @message NoticeResponse
  defmodule NoticeResponse do
    defstruct Error.fields()

    @type t() :: %__MODULE__{
            severity: String.t(),
            code: String.t(),
            message: String.t(),
            detail: String.t(),
            hint: String.t(),
            position: String.t(),
            internal_position: String.t(),
            query: String.t(),
            where: String.t(),
            schema: String.t(),
            table: String.t(),
            column: String.t(),
            data_type: String.t(),
            constraint: String.t(),
            file: String.t(),
            line: String.t(),
            routine: String.t()
          }

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        Error.encode(m, "N")
      end
    end
  end

  @message NotificationResponse
  defmodule NotificationResponse do
    defstruct [:pid, :channel, :payload]

    @type t() :: %__MODULE__{pid: integer(), channel: String.t(), payload: String.t()}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        payload =
          <<m.pid::i32(), string(m.channel)::binary, string(m.payload)::binary>>

        <<"A", mlen(payload)::i32(), payload::binary>>
      end
    end
  end

  @message ParameterDescription
  defmodule ParameterDescription do
    defstruct [:params]

    @type t() :: %__MODULE__{params: [integer()]}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        params = Enum.map(m.params, &<<&1::i32()>>) |> IO.iodata_to_binary()

        payload = <<length(m.params)::i16(), params::binary>>

        <<"t", mlen(payload)::i32(), payload::binary>>
      end
    end
  end

  @message ParameterStatus
  defmodule ParameterStatus do
    defstruct [:name, :value]

    @type t() :: %__MODULE__{name: String.t(), value: String.t()}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        payload = <<string(m.name)::binary, string(m.value)::binary>>
        <<"S", mlen(payload)::i32(), payload::binary>>
      end
    end
  end

  @message Parse
  defmodule Parse do
    defstruct [:name, :query, :params]

    @type t() :: %__MODULE__{name: String.t(), query: String.t(), params: [integer()]}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(m) do
        params = Enum.map(m.params, &<<&1::i32()>>) |> IO.iodata_to_binary()

        payload =
          <<string(m.name)::binary, string(m.query)::binary, length(m.params)::i16(),
            params::binary>>

        <<"P", mlen(payload)::i32(), payload::binary>>
      end
    end
  end

  @message ParseComplete
  defmodule ParseComplete do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(_m) do
        <<"1", 4::i32()>>
      end
    end
  end

  @message PasswordMessage
  defmodule PasswordMessage do
    defstruct [:password]

    @type t() :: %__MODULE__{password: String.t()}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(m) do
        password = string(m.password)
        <<"p", mlen(password)::i32(), password::binary>>
      end
    end
  end

  @message PortalSuspended
  defmodule PortalSuspended do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(_m) do
        <<"s", 4::i32()>>
      end
    end
  end

  @message Query
  defmodule Query do
    defstruct [:query]

    @type t() :: %__MODULE__{query: String.t()}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(m) do
        query = string(m.query)
        <<"Q", mlen(query)::i32(), query::binary>>
      end
    end
  end

  @message ReadyForQuery
  defmodule ReadyForQuery do
    defstruct [:status]

    @type t() :: %__MODULE__{status: :idle | :tx | :failed}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        <<"Z", 5::i32(), status(m)::binary-1>>
      end

      defp status(%{status: :idle}), do: "I"
      defp status(%{status: :tx}), do: "T"
      defp status(%{status: :failed}), do: "E"
    end
  end

  @message RowDescription
  defmodule RowDescription do
    defmodule Field do
      defstruct [:name, :oid, :attnum, :type, :typlen, :typmod, :fmt]

      @type t() :: %__MODULE__{
              name: String.t(),
              oid: integer(),
              attnum: integer(),
              type: integer(),
              typlen: integer(),
              typmod: integer(),
              fmt: integer()
            }

      defimpl Encoder do
        def encode(f) do
          <<string(f.name)::binary, f.oid::i32(), f.attnum::i16(), f.type::i32(), f.typlen::i16(),
            f.typmod::i32(), f.fmt::i16()>>
        end
      end
    end

    defstruct fields: []

    @type t() :: %__MODULE__{fields: [Field.t()]}

    def source, do: [:backend]

    defimpl Encoder do
      def encode(m) do
        fields =
          [<<length(m.fields)::i16()>> | Enum.map(m.fields, &Encoder.encode/1)]
          |> IO.iodata_to_binary()

        <<"T", mlen(fields)::i32(), fields::binary>>
      end
    end
  end

  @message SASLInitialResponse
  defmodule SASLInitialResponse do
    defstruct [:name, :response]

    @type t() :: %__MODULE__{name: String.t(), response: binary()}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(m) do
        response =
          if m.response do
            <<byte_size(m.response)::i32(), m.response::binary>>
          else
            <<-1::i32()>>
          end

        payload = <<string(m.name)::binary, response::binary>>

        <<"p", mlen(payload)::i32(), payload::binary>>
      end
    end
  end

  @message SASLResponse
  defmodule SASLResponse do
    defstruct [:data]

    @type t() :: %__MODULE__{data: binary()}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(m) do
        <<"p", mlen(m.data)::i32(), m.data::binary>>
      end
    end
  end

  @message SSLRequest
  defmodule SSLRequest do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(_m) do
        <<8::i32(), 1234::i16(), 5679::i16()>>
      end
    end
  end

  @message StartupMessage
  defmodule StartupMessage do
    defstruct version: {3, 0}, params: %{}

    @type t() :: %__MODULE__{version: {integer(), integer()}, params: %{String.t() => String.t()}}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(m) do
        %{version: {maj, min}} = m

        payload =
          Enum.reduce(
            m.params,
            [<<maj::i16(), min::i16()>>],
            fn {k, v}, acc ->
              [acc, <<string(k)::binary, string(v)::binary>>]
            end
          )
          |> IO.iodata_to_binary()
          |> string()

        <<mlen(payload)::i32(), payload::binary>>
      end
    end
  end

  @message Sync
  defmodule Sync do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(_m) do
        <<"S", 4::i32()>>
      end
    end
  end

  @message Terminate
  defmodule Terminate do
    defstruct []

    @type t() :: %__MODULE__{}

    def source, do: [:frontend]

    defimpl Encoder do
      def encode(_m) do
        <<"X", 4::i32()>>
      end
    end
  end

  #####################################################################

  @spec inspect(term()) :: binary()
  def inspect(msg) do
    inspect(msg,
      charlists: :as_lists,
      width: 80,
      pretty: true,
      syntax_colors: [atom: :green]
    )
  end

  # build type specification from list of modules
  m_t = fn m -> quote(do: unquote(m).t()) end

  typespec = fn
    [m], _ ->
      m_t.(m)

    [m | rest], f ->
      {:|, [], [m_t.(m), f.(rest, f)]}
  end

  @message_types @message
                 |> Enum.reverse()
                 |> Enum.map(&Module.concat(__MODULE__, &1))

  @type t() :: unquote(typespec.(@message_types, typespec))

  def types do
    @message_types
  end
end
