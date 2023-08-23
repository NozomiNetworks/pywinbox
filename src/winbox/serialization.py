import struct
from typing import Any


class StringWriter:
    data: str

    def __init__(self, data: bytearray = bytearray()):
        if data is None or not isinstance(data, bytearray):
            raise ValueError(data)

        self.data = data

    def write(self, format: str, value: Any, endianess: str = '<') -> int:
        self.data += bytearray(struct.pack(f'{endianess}{format}', value))

    def write_signed_int_8(self, value: int, endianess: str = '<') -> None:
        self.write('b', value, endianess)

    def write_signed_int_16(self, value: int, endianess: str = '<') -> None:
        self.write('h', value, endianess)

    def write_signed_int_32(self, value: int, endianess: str = '<') -> None:
        self.write('l', value, endianess)

    def write_signed_int_64(self, value: int, endianess: str = '<') -> None:
        self.write('q', value, endianess)

    def write_unsigned_int_8(self, value: int, endianess: str = '<') -> None:
        self.write('B', value, endianess)

    def write_unsigned_int_16(self, value: int, endianess: str = '<') -> None:
        self.write('H', value, endianess)

    def write_unsigned_int_32(self, value: int, endianess: str = '<') -> None:
        self.write('L', value, endianess)

    def write_unsigned_int_64(self, value: int, endianess: str = '<') -> None:
        self.write('Q', value, endianess)

    def write_ipv6(self, value: str) -> None:
        if value is None or len(value) != 16*2:
            raise ValueError(value)

        self.write_bytes(bytearray.fromhex(value))

    def write_bytes(self, value: str) -> None:
        if value is None or len(value) <= 0:
            raise ValueError(value)

        for byte in value:
            self.data.append(byte)

    def write_string(self, value: str, encoding: str = 'utf-8') -> None:
        if value is None or len(value) <= 0:
            raise ValueError(value)

        self.write_bytes(str(value).encode(encoding))


class StringReader:
    data: str
    position: int

    def __init__(self, data: str):
        if data is None or data == '':
            raise ValueError(data)

        self.data = data
        self.position = 0

    def eof(self) -> bool:
        return self.position >= len(self.data)

    def len(self) -> int:
        return len(self.data)

    def remaining(self) -> int:
        return len(self.data) - self.position

    def read_signed_int_8(self, endianess: str = '<') -> int:
        return self.read('b', 1, endianess)

    def read_signed_int_16(self, endianess: str = '<') -> int:
        return self.read('h', 2, endianess)

    def read_signed_int_32(self, endianess: str = '<') -> int:
        return self.read('l', 4, endianess)

    def read_signed_int_64(self, endianess: str = '<') -> int:
        return self.read('q', 8, endianess)

    def read_unsigned_int_8(self, endianess: str = '<') -> int:
        return self.read('B', 1, endianess)

    def read_unsigned_int_16(self, endianess: str = '<') -> int:
        return self.read('H', 2, endianess)

    def read_unsigned_int_32(self, endianess: str = '<') -> int:
        return self.read('L', 4, endianess)

    def read_unsigned_int_64(self, endianess: str = '<') -> int:
        return self.read('Q', 8, endianess)

    def read_ipv6(self) -> str:
        ipv6 = ''
        for i in range(16):
            ipv6 += hex(self.read_byte())[2:]
        return ipv6

    def read_bytes(self, size: int) -> str:
        if size <= 0 or self.remaining() < size:
            raise ValueError(size)

        try:
            return self.data[self.position:self.position+size]
        finally:
            self.position += size

    def read_string(self, size: int, encoding: str = 'utf-8') -> str:
        if size <= 0 or self.remaining() < size:
            raise ValueError(size)

        try:
            return self.data[self.position:self.position+size].decode(encoding)
        finally:
            self.position += size

    def read(self, format: str, size: int, endianess: str = '<') -> int:
        if size <= 0 or self.remaining() < size:
            raise ValueError(size)

        try:
            return struct.unpack(f'{endianess}{format}', self.data[self.position:self.position+size])[0]
        finally:
            self.position += size
