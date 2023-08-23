from abc import ABC, abstractmethod
from ast import Dict
from typing import Any, List
from winbox.variable_name import VariableName
from winbox.variable_type import VariableType
from winbox.variable_size import VariableSize


class Variable(ABC):
    type: int
    name: int
    value: Any

    def __init__(self, type: int, name: int, value: Any = None) -> None:
        if isinstance(type, VariableType):
            type = type.value
        if isinstance(name, VariableName):
            name = name.value
        self.type = type
        self.name = name
        self.value = value

    def get_name(self) -> int:
        return self.name

    def get_type(self) -> int:
        return self.type

    def get_friendly_name(self) -> str:
        try:
            return VariableName(self.name).name
        except ValueError:
            return f'{self.name}'

    def get_friendly_type(self) -> str:
        try:
            return VariableType(self.type).name
        except ValueError:
            return f'unknown({self.type})'

    def get_friendly_type_and_name(self) -> str:
        return f'{self.get_friendly_type()}.{self.get_friendly_name()}'

    def get_friendly_value(self) -> str:
        return str(self.value)

    def is_of(self, type: VariableType):
        return self.type == type.value

    def json(self) -> Dict:
        return {
            'name': self.get_friendly_name(),
            'type': self.get_friendly_type(),
            'value': self.get_friendly_value()
        }

    @abstractmethod
    def is_short(self) -> bool:
        pass

    @abstractmethod
    def length(self) -> int:
        pass


class BooleanVariable(Variable):
    value: bool

    def __init__(self, name: int, value: bool) -> None:
        super().__init__(VariableType.BOOL.value, name, value)

    def is_short(self) -> bool:
        return self.value

    def length(self) -> int:
        return 0


class DwordVariable(Variable):
    value: int

    def __init__(self, name: int, value: int) -> None:
        if value < 0 or value >= pow(2, 32):
            raise ValueError(value)
        super().__init__(VariableType.DWORD.value, name, value)

    def is_short(self) -> bool:
        return self.value < pow(2, 8)

    def length(self) -> int:
        if self.value < pow(2, 8):
            return VariableSize.BYTE.value
        return VariableSize.DWORD.value


class QwordVariable(Variable):
    value: int

    def __init__(self, name: int, value: int) -> None:
        if value < 0 or value >= pow(2, 64):
            raise ValueError(value)
        super().__init__(VariableType.QWORD.value, name, value)

    def is_short(self) -> bool:
        return False

    def length(self) -> int:
        return VariableSize.QWORD.value


class IPv6Variable(Variable):
    value: str

    def __init__(self, name: int, value: str) -> None:
        if not isinstance(value, str) or len(value) != 2 * VariableSize.IP6.value:
            raise ValueError(value)
        super().__init__(VariableType.IP6.value, name, value)

    def is_short(self) -> bool:
        return False

    def length(self) -> int:
        return VariableSize.IP6.value


class RawVariable(Variable):
    value: str

    def __init__(self, name: int, value: bytearray) -> None:
        if value is None or len(value) < 0 or len(value) >= pow(2, 16):
            raise ValueError(value)
        super().__init__(VariableType.RAW.value, name, value)

    def is_short(self) -> bool:
        return len(self.value) < pow(2, 8)

    def length(self) -> int:
        if self.is_short():
            return VariableSize.BYTE.value + len(self.value)
        return VariableSize.SHORT.value + len(self.value)

    def get_friendly_value(self) -> str:
        return self.value.hex()


class StringVariable(RawVariable):
    def __init__(self, name: int, value: str) -> None:
        super().__init__(name, value)
        self.type = VariableType.STRING.value

    def get_friendly_value(self) -> str:
        return self.value


class VariableArray(Variable):
    value: List

    def __init__(self, type: int, name: int, value: Any = None) -> None:
        if isinstance(value, list):
            if len(value) >= pow(2, 16):
                raise OverflowError(value)
            super().__init__(type, name, value)
        elif value is None:
            super().__init__(type, name, [])
        else:
            super().__init__(type, name, [value])

    def add(self, value: Any) -> None:
        if len(self.value) >= pow(2, 16):
            raise OverflowError(self.value)
        self.value.append(value)

    def get(self, index: int) -> Any:
        return self.value[index]

    def is_short(self) -> bool:
        return False

    def length(self) -> int:
        inner_type = VariableType(self.type ^ VariableType.BOOL_ARRAY.value)
        return VariableSize.SHORT.value + len(self.value) * VariableSize[inner_type.name].value


class BooleanVariableArray(VariableArray):
    value: List[bool]

    def __init__(self, name: int, value: Any = None) -> None:
        super().__init__(VariableType.BOOL_ARRAY.value, name, value)


class DwordVariableArray(VariableArray):
    value: List[int]

    def __init__(self, name: int, value: Any = None) -> None:
        super().__init__(VariableType.DWORD_ARRAY.value, name, value)


class QwordVariableArray(VariableArray):
    value: List[int]

    def __init__(self, name: int, value: Any = None) -> None:
        super().__init__(VariableType.QWORD_ARRAY.value, name, value)


class Ipv6VariableArray(VariableArray):
    def __init__(self, name: int, value: Any = None) -> None:
        super().__init__(VariableType.IP6_ARRAY.value, name, value)


class SequenceVariableArray(VariableArray):
    value: List[str]

    def __init__(self, type: int, name: int, value: Any = None) -> None:
        super().__init__(type, name, value)

    def length(self) -> int:
        return VariableSize.SHORT.value + \
               len(self.value) * VariableSize.SHORT.value + \
               sum(map(len, self.value))


class StringVariableArray(SequenceVariableArray):
    def __init__(self, name: int, value: Any = None) -> None:
        super().__init__(VariableType.STRING_ARRAY.value, name, value)


class RawVariableArray(SequenceVariableArray):
    def __init__(self, name: int, value: Any = None) -> None:
        super().__init__(VariableType.RAW_ARRAY.value, name, value)
