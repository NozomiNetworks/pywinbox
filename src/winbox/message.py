from logger import log
from typing import Any, Dict, List
from winbox.variable_name import VariableName
from winbox.variable_type import VariableType
from winbox.serialization import StringReader, StringWriter
from winbox.variable import Variable, SequenceVariableArray, BooleanVariable, DwordVariable, QwordVariable, IPv6Variable, RawVariable, StringVariable, RawVariableArray, BooleanVariableArray, DwordVariableArray, QwordVariableArray, Ipv6VariableArray, StringVariableArray  # noqa: E501
from re import match, IGNORECASE


class Header:
    chuk_offset: int
    type_id: int
    length: int

    def __init__(self, chunk_offset: int = 0, type_id: int = 0, length: int = 0) -> None:
        self.chuk_offset = chunk_offset
        self.type_id = type_id
        self.length = length

    def json(self) -> Dict:
        return {
            'chunk_offset': self.chuk_offset,
            'type_id': self.type_id,
            'length': self.length
        }


class Message:
    MAGIC = 'M2'
    magic: str
    variables: List[Variable]

    def __init__(self, data: bytes = None):
        self.variables = []

        if data is None:
            self.magic = self.MAGIC
            return

        reader = StringReader(data)
        self.magic = reader.read_string(2)
        if self.magic != Message.MAGIC:
            log(f'Unexpected Message data: {data}')
            raise ValueError(data)

        while not reader.eof():
            type_and_name = reader.read_unsigned_int_32()
            type = VariableType(type_and_name & 0xf8000000)
            name = type_and_name & 0x00ffffff

            variable = None
            if type == VariableType.BOOL:
                variable = BooleanVariable(
                    name, (type_and_name & VariableType.SHORT_LENGTH.value) != 0)
            elif type == VariableType.DWORD:
                if type_and_name & VariableType.SHORT_LENGTH.value:
                    variable = DwordVariable(
                        name, reader.read_unsigned_int_8())
                else:
                    variable = DwordVariable(
                        name, reader.read_unsigned_int_32())
            elif type == VariableType.QWORD:
                variable = QwordVariable(name, reader.read_unsigned_int_64())
            elif type == VariableType.IP6:
                variable = IPv6Variable(name, reader.read_ipv6())
            elif type == VariableType.RAW or type == VariableType.STRING:
                len = 0
                if type_and_name & VariableType.SHORT_LENGTH.value:
                    len = reader.read_unsigned_int_8()
                else:
                    len = reader.read_unsigned_int_16()
                if type == VariableType.RAW:
                    variable = RawVariable(name, reader.read_bytes(len))
                else:
                    variable = StringVariable(name, reader.read_string(len))
            elif type == VariableType.MESSAGE:
                len = 0
                if type_and_name & VariableType.SHORT_LENGTH.value:
                    len = reader.read_unsigned_int_8()
                else:
                    len = reader.read_unsigned_int_16()
                variable = MessageVariable(
                    name, self.deserialize(reader.read_bytes(len)))
            elif type == VariableType.BOOL_ARRAY:
                variable = BooleanVariableArray(name)
                for i in range(reader.read_unsigned_int_16()):
                    variable.add(reader.read_unsigned_int_8() == 1)
            elif type == VariableType.DWORD_ARRAY:
                variable = DwordVariableArray(name)
                for i in range(reader.read_unsigned_int_16()):
                    variable.add(reader.read_unsigned_int_32())
            elif type == VariableType.QWORD_ARRAY:
                variable = QwordVariableArray(name)
                for i in range(reader.read_unsigned_int_16()):
                    variable.add(reader.read_unsigned_int_64())
            elif type == VariableType.IP6_ARRAY:
                variable = Ipv6VariableArray(name)
                for i in range(reader.read_unsigned_int_16()):
                    variable.add(name, reader.read_ipv6())
            elif type == VariableType.RAW_ARRAY or type == VariableType.STRING_ARRAY:
                if type is VariableType.RAW:
                    variable = RawVariableArray(name)
                else:
                    variable = StringVariableArray(name)
                for i in range(reader.read_unsigned_int_16()):
                    len = reader.read_unsigned_int_16()
                    if type is VariableType.RAW:
                        variable.add(reader.read_bytes(len))
                    else:
                        variable.add(reader.read_string(len))
            elif type == VariableType.MESSAGE_ARRAY:
                variable = MessageVariableArray(name)
                for i in range(reader.read_unsigned_int_16()):
                    len = reader.read_unsigned_int_16()
                    variable.add(self.deserialize(reader.read_bytes(len)))
            else:
                raise ValueError(type)

            self.add_variable(variable)

    def get_magic(self) -> str:
        return self.magic

    def get_variables(self) -> list[Variable]:
        return self.variables

    def add_variable(self, variable: Variable) -> None:
        self.variables.append(variable)

    # def get_variable(self, type: int, name: int) -> Variable:
    #     if isinstance(type, VariableType):
    #         type = type.value
    #     if isinstance(type, VariableName):
    #         name = name.value
    #     for variable in self.variables:
    #         if variable.type == type and variable.name == name:
    #             return variable

    def get_variable(self, name: int) -> Variable:
        if isinstance(name, VariableName):
            name = name.value
        for variable in self.variables:
            if isinstance(name, str) and match(name, str(variable.get_friendly_type_and_name()), IGNORECASE):
                return variable
            elif variable.name == name:
                return variable

    def has_exactly(self, *names: VariableName) -> bool:
        if len(self.variables) != len(names):
            return False
        for i in range(len(names)):
            if self.variables[i].name != names[i]:
                return False
        return True

    def has_only(self, *names: VariableName) -> bool:
        variables: dict[int, Variable] = {}
        for name in names:
            variable = self.get_variable(name)
            if variable is None:
                return False
            else:
                variables[variable.get_name()] = variable

        for variable in self.variables:
            if variables.get(variable.get_name()) is None:
                return False

        return True

    def has(self, *names: VariableName) -> bool:
        for name in names:
            if self.get_variable(name) is not None:
                return True

        return False

    def has_with_value(self, nav: dict):
        for name, value in nav.items():
            variable = self.get_variable(name)
            if variable is None or (value != '*' and variable.value != value):
                return False
        return True

    def has_only_with_value(self, nav: dict):
        if not self.has_only(*nav.keys()):
            return False

        return self.has_with_value(nav)

    def json(self) -> Dict:
        return {
            'magic': self.magic,
            'variables': [var.json() for var in self.variables]
        }

    def length(self) -> int:
        # M2 [type_and_value+len]
        return 2 + sum(var.length() + 4 for var in self.variables)

    def serialize(self) -> bytes:
        data = bytearray()
        writer = StringWriter(data)

        writer.write_string('M2')

        for variable in self.get_variables():
            type_and_name = variable.get_type() | variable.get_name()
            if variable.is_short():
                type_and_name |= VariableType.SHORT_LENGTH.value

            writer.write_unsigned_int_32(type_and_name)

            if variable.is_of(VariableType.DWORD):
                if variable.is_short():
                    writer.write_unsigned_int_8(variable.value)
                else:
                    writer.write_unsigned_int_32(variable.value)
            elif variable.is_of(VariableType.QWORD):
                writer.write_unsigned_int_64(variable.value)
            elif variable.is_of(VariableType.IP6):
                writer.write_ipv6(variable.value)
            elif variable.is_of(VariableType.STRING) or variable.is_of(VariableType.RAW):
                if variable.is_short():
                    writer.write_unsigned_int_8(variable.length()-1)
                else:
                    writer.write_unsigned_int_16(variable.length()-2)

                if variable.is_of(VariableType.STRING):
                    writer.write_string(variable.value)
                else:
                    writer.write_bytes(bytearray(variable.value))
            elif variable.is_of(VariableType.MESSAGE):
                raise NotImplementedError()
            elif variable.is_of(VariableType.BOOL_ARRAY):
                writer.write_unsigned_int_16(len(variable.value))
                for value in variable.value:
                    writer.write_unsigned_int_8(value)
            elif variable.is_of(VariableType.DWORD_ARRAY):
                writer.write_unsigned_int_16(len(variable.value))
                for value in variable.value:
                    writer.write_unsigned_int_32(value)
            elif variable.is_of(VariableType.QWORD_ARRAY):
                writer.write_unsigned_int_16(len(variable.value))
                for value in variable.value:
                    writer.write_unsigned_int_64(value)
            elif variable.is_of(VariableType.IP6_ARRAY):
                writer.write_unsigned_int_16(len(variable.value))
                for value in variable.value:
                    writer.write_ipv6(value)
            elif variable.is_of(VariableType.STRING_ARRAY) or variable.is_of(VariableType.RAW_ARRAY):
                writer.write_unsigned_int_16(len(variable.value))
                for value in variable.value:
                    writer.write_unsigned_int_16(len(value))
                    if variable.is_of(VariableType.STRING_ARRAY):
                        writer.write_string(value)
                    else:
                        writer.write_bytes(value)
            elif variable.is_of(VariableType.MESSAGE_ARRAY):
                raise NotImplementedError()

        return data


class Frame:
    header: Header
    message: Message

    def __init__(self, header: Header = None, message: Message = None, data: bytes = None, answer_to: Message = None,
                 decryption_func=None):
        if data is not None:
            reader = StringReader(data)
            chunk_offset = reader.read_unsigned_int_8()
            type_id = reader.read_unsigned_int_8()
            length = reader.read_unsigned_int_16('>')
            self.header = Header(chunk_offset, type_id, length)
            self.message = Message(decryption_func(data))

        else:
            self.header = header
            self.message = message
            if header is None:
                self.header = Header()
            if message is None:
                self.message = Message()
            # Swap SYS_TO with SYS_FROM
            if answer_to is not None:
                self.header.type_id = 1
                if answer_to.has(VariableName.SYS_FROM):
                    self.message.add_variable(
                        DwordVariableArray(VariableName.SYS_TO,
                                           answer_to.get_variable(VariableName.SYS_FROM).value.copy()))
                if answer_to.has(VariableName.SYS_TO):
                    self.message.add_variable(
                        DwordVariableArray(VariableName.SYS_FROM,
                                           answer_to.get_variable(VariableName.SYS_TO).value.copy()))

    def json(self) -> Dict:
        return {
            'header': self.header.json(),
            'message': self.message.json()
        }

    def serialize(self, encryption_func) -> bytes:
        data = bytearray()
        writer = StringWriter(data)

        # Code from removed self.prepare method
        self.header.length = self.message.length()
        self.header.chuk_offset = self.header.length + 2

        writer.write_unsigned_int_8(min(255, self.header.chuk_offset))
        writer.write_unsigned_int_8(self.header.type_id)
        writer.write_unsigned_int_16(self.header.length, '>')

        payload = encryption_func(self.message.serialize())

        if len(payload) > 255:
            chunk_start = 0
            chunk_end = 0xfd

            while chunk_start < len(payload):
                if chunk_start > 0:
                    writer.write_unsigned_int_8(
                        min(255, len(payload[chunk_start:])))
                    writer.write_unsigned_int_8(255)
                writer.write_bytes(payload[chunk_start:chunk_end])

                chunk_start = chunk_end
                chunk_end = chunk_start + min(255, len(payload[chunk_start:]))
        else:
            writer.write_bytes(payload)

        return data


class MessageVariable(Variable):
    value: Message

    def __init__(self, name: int, value: Message = None) -> None:
        super().__init__(VariableType.MESSAGE.value, name, value)

    def is_short(self) -> bool:
        return False

    def length(self) -> int:
        return self.value.length


class MessageVariableArray(SequenceVariableArray):
    value: List[Message]

    def __init__(self, name: int, value: Any = None) -> None:
        super().__init__(VariableType.MESSAGE_ARRAY.value, name, value)
