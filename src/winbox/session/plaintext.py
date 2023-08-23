from configparser import SectionProxy
from winbox.message import Message
from winbox.serialization import StringReader, StringWriter
from winbox.session.session import ClientMgr, UpstreamMgr

MAGIC = 1
NEEDS_LOGIN = False


class Client(ClientMgr):

    def is_logged(self):
        return True

    async def login(self, data):
        # This method should never be reached as 'NEEDS_LOGIN' is False
        raise NotImplementedError

    def encrypt_payload(self, payload):
        return payload

    def decrypt_payload(self, payload):
        payload = self.extract_payload(payload)
        return payload

    @staticmethod
    def extract_payload(data: bytes) -> bytes:
        payload = b''

        reader = StringReader(data)
        chunk_offset = reader.read_unsigned_int_8()
        reader.read_unsigned_int_8()  # Discard type_id byte
        length = reader.read_unsigned_int_16('>')

        if chunk_offset == 255 and length > 255:
            chunk_size = 0xfd
            while not reader.eof():
                payload += reader.read_bytes(chunk_size)
                if reader.eof():
                    break
                chunk_size = reader.read_unsigned_int_8()
                if reader.read_unsigned_int_8() != 255:
                    raise ValueError(data)
        else:
            payload = reader.read_bytes(length)

        return payload

    def join_payload(self, data: bytes) -> bytes:
        payload = b''

        reader = StringReader(data)
        chunk_offset = reader.read_unsigned_int_8()
        reader.read_unsigned_int_8()  # Discard type_id byte
        length = reader.read_unsigned_int_16('>')

        if chunk_offset == 255 and length > 255:
            chunk_size = 0xfd
            while not reader.eof():
                payload += reader.read_bytes(chunk_size)
                if reader.eof():
                    break
                chunk_size = reader.read_unsigned_int_8()
                if reader.read_unsigned_int_8() != 255:
                    raise ValueError(data)
        else:
            payload = reader.read_bytes(length)

        return payload

    async def send_message(self, msg: Message):
        data = bytearray()
        writer = StringWriter(data)

        # Code from removed Frame.prepare method
        hdr_length = msg.length()
        hdr_chunk_offset = hdr_length + 2

        writer.write_unsigned_int_8(min(255, hdr_chunk_offset))
        writer.write_unsigned_int_8(MAGIC)
        writer.write_unsigned_int_16(hdr_length, '>')

        payload = msg.serialize()
        if len(payload) > 255:
            chunk_start = 0
            chunk_end = 0xfd

            while chunk_start < len(payload):
                if chunk_start > 0:
                    writer.write_unsigned_int_8(min(255, len(payload[chunk_start:])))
                    writer.write_unsigned_int_8(255)
                writer.write_bytes(payload[chunk_start:chunk_end])

                chunk_start = chunk_end
                chunk_end = chunk_start + min(255, len(payload[chunk_start:]))
        else:
            writer.write_bytes(payload)

        await self.send_raw(data)

    def recv_message(self) -> Message:
        raise NotImplementedError


class Upstream(UpstreamMgr):

    def __init__(self, config: SectionProxy):
        super().__init__(config)
        self.open_socket()

    def login(self):
        # This method should never be reached as 'NEEDS_LOGIN' is False
        raise NotImplementedError

    async def send_message(self, msg: Message):
        data = bytearray()
        writer = StringWriter(data)

        # Code from removed Frame.prepare method
        hdr_length = msg.length()
        hdr_chunk_offset = hdr_length + 2

        writer.write_unsigned_int_8(min(255, hdr_chunk_offset))
        writer.write_unsigned_int_8(MAGIC)
        writer.write_unsigned_int_16(hdr_length, '>')

        payload = msg.serialize()
        if len(payload) > 255:
            chunk_start = 0
            chunk_end = 0xfd

            while chunk_start < len(payload):
                if chunk_start > 0:
                    writer.write_unsigned_int_8(min(255, len(payload[chunk_start:])))
                    writer.write_unsigned_int_8(255)
                writer.write_bytes(payload[chunk_start:chunk_end])

                chunk_start = chunk_end
                chunk_end = chunk_start + min(255, len(payload[chunk_start:]))
        else:
            writer.write_bytes(payload)

        await self.send_raw(data)

    def recv_message(self) -> Message:
        raise NotImplementedError

    def encrypt_payload(self, payload):
        return payload

    def decrypt_payload(self, payload):

        payload = self.extract_payload(payload)
        return payload

    @staticmethod
    def extract_payload(data: bytes) -> bytes:
        payload = b''

        reader = StringReader(data)
        chunk_offset = reader.read_unsigned_int_8()
        reader.read_unsigned_int_8()  # Discard type_id byte
        length = reader.read_unsigned_int_16('>')

        if chunk_offset == 255 and length > 255:
            chunk_size = 0xfd
            while not reader.eof():
                payload += reader.read_bytes(chunk_size)
                if reader.eof():
                    break
                chunk_size = reader.read_unsigned_int_8()
                if reader.read_unsigned_int_8() != 255:
                    raise ValueError(data)
        else:
            payload = reader.read_bytes(length)

        return payload
