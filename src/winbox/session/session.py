import asyncio
from logger import log
from uuid import UUID, uuid4
from configparser import SectionProxy
from winbox.message import Message, Frame
from socket import socket, AF_INET, SOCK_STREAM

BUFFER_SIZE: int = 4096
TIMEOUT: int = 2


class InvalidUsername(Exception):
    pass


class Session:
    id: UUID
    client_reader: asyncio.StreamReader
    client_writer: asyncio.StreamWriter
    protocol = None
    client = None

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: SectionProxy) -> None:
        self.id = uuid4()
        self.client_reader = reader
        self.client_writer = writer
        self.config = config

    def set_protocol(self, protocol):
        self.protocol = protocol
        self.client = self.protocol.Client(self.client_reader, self.client_writer, self.config)

    async def login(self, data: bytes) -> bytes:
        data = await self.client.login(data)
        return data

    def close(self):
        self.client_writer.close()


class ServerSession(Session):
    opened_file = ''
    stdid = 0
    fs = {}

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: SectionProxy) -> None:
        super().__init__(reader, writer, config)
        self.init_fs()

    def init_fs(self):
        self.fs['/etc/passwd'] = b'>>This is the content of passwd<<'
        with open(self.config['shared']['users_file'], 'rb') as fd:
            self.fs['/flash/rw/store/user.dat'] = fd.read()


class ProxySession(Session):

    upstream = None

    def set_protocol(self, protocol):
        super().set_protocol(protocol)
        self.upstream = self.protocol.Upstream(self.config)

    def close(self):
        super().close()
        if self.upstream is not None:
            self.upstream.close()

    async def login(self, data):
        data = await super().login(data)

        log('upstream', session=self, message="Logging in to upstream")
        self.upstream.login()
        log('upstream', session=self, message="Login to upstream OK")

        return data


class ClientMgr:

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: SectionProxy):
        self.reader = reader
        self.writer = writer
        self.config = config

    def is_logged(self):
        raise NotImplementedError

    async def login(self, data: bytes):
        raise NotImplementedError

    def encrypt_payload(self, payload):
        raise NotImplementedError

    def decrypt_payload(self, payload):
        raise NotImplementedError

    def extract_payload(self, data: bytes) -> bytes:
        raise NotImplementedError

    def split_payload(self, data: bytes) -> bytes:
        raise NotImplementedError

    async def send_raw(self, data: bytes):
        self.writer.write(data)
        await self.writer.drain()

    async def recv_raw(self):
        return await asyncio.wait_for(self.reader.read(BUFFER_SIZE), timeout=TIMEOUT)

    async def send_message(self, msg: Message):
        raise NotImplementedError

    def recv_message(self) -> Message:
        raise NotImplementedError

    def serialize(self, frame: Frame) -> bytes:
        return frame.serialize(self.encrypt_payload, self.split_payload)

    def deserialize(self, data: bytes) -> Frame:
        return Frame(data=data, decryption_func=self.decrypt_payload)


class UpstreamMgr:

    def __init__(self, config: SectionProxy):
        self.host = config['proxy']['upstream_host']
        self.port = config['proxy'].getint('upstream_port')
        # Inheriting class must open the socket
        # self.open_socket()
        self.socket = None

    def login(self):
        raise NotImplementedError

    async def send_raw(self, data: bytes):
        self.socket.send(data)

    async def recv_raw(self) -> bytes:
        return self.socket.recv(BUFFER_SIZE)

    async def send_message(self, msg: Message):
        raise NotImplementedError

    def recv_message(self) -> Message:
        raise NotImplementedError

    def close(self):
        if self.socket is not None:
            self.socket.close()
        log('upstream', message="Session terminated")

    def open_socket(self):
        log('upstream', message=f'Opening socket to {self.host}:{self.port}')
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        self.socket.settimeout(TIMEOUT)

    def encrypt_payload(self, payload):
        raise NotImplementedError

    def decrypt_payload(self, payload):
        raise NotImplementedError

    # TODO: Avoid reimplementing the same method as the client
    def extract_payload(self, data: bytes) -> bytes:
        raise NotImplementedError

    def split_payload(self, data: bytes) -> bytes:
        raise NotImplementedError

    def serialize(self, frame: Frame) -> bytes:
        return frame.serialize(self.encrypt_payload, self.split_payload)

    def deserialize(self, data: bytes) -> Frame:
        return Frame(data=data, decryption_func=self.decrypt_payload)
