#!/usr/bin/env python3

import os
import re
import sys
import traceback
import asyncio
import importlib
from socket import timeout
from enum import auto, Enum
from datetime import datetime
from logger import logger_init, log
from detection.engine import Engine
from configparser import ConfigParser
from winbox.message import Frame, Message
from winbox.session.session import Session
from winbox.variable_name import VariableName


class IgnorePacket(Exception):
    pass


class Command(Enum):
    UNKNOWN = auto()
    READ_OPEN = auto()
    READ_READ = auto()
    READ_CANCEL = auto()
    LOGIN_HASH_REQ = auto()
    LOGIN_LOGIN = auto()
    LOGIN_SYS_INFO = auto()
    CREATE_FILE = auto()
    FILEMAN_OPEN = auto()
    FILEMAN_READ = auto()
    DNS_REQ = auto()


class Pywinbox:
    TIMEOUT: int = 30
    BUFFER_SIZE: int = 4096
    protocols = {}
    config: ConfigParser

    def __init__(self, config: ConfigParser) -> None:

        self.config = ConfigParser()
        self.config.read('config.ini')
        logger_init(self.config)
        self.load_protocols()
        self.engine = Engine()
        self.winbox_dump = os.path.join(self.config['shared']['dump_folder'], 'winbox')
        self.other_dump = os.path.join(self.config['shared']['dump_folder'], 'other')

        # Create dump folders if they don't exist
        if not os.path.exists(self.winbox_dump):
            os.makedirs(self.winbox_dump)
        if not os.path.exists(self.other_dump):
            os.makedirs(self.other_dump)

    async def run(self):
        try:
            server = await asyncio.start_server(self.handle_client, self.ip, self.port)
            log('control', message=f'Starting Pywinbox. Listening on {self.ip}:{self.port}')
        except OSError:
            return

        try:
            async with server:
                await server.serve_forever()
        finally:
            log('control', message='exiting')

    def load_protocols(self):
        protocol_names = [protocol.strip() for protocol in self.config['shared']['protocols'].split(',')]
        for protocol_name in protocol_names:
            self.protocols[protocol_name] = importlib.import_module('winbox.session.' + protocol_name)

    def get_winbox_protocol(self, data: bytes) -> str:
        for name, protocol in self.protocols.items():
            if data[1] == protocol.MAGIC:
                return name
        return None

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        data = None
        session = self.new_session(reader, writer)
        log('info', session=session, message='Incoming connection')

        while True:
            try:
                # Receive data from client and parse it info a Frame
                request = await self.recv_from_client(session)
                if request is None:
                    break

                self.scan_request(session, request)

                response = await self.handle_request(session, request)

                # Send data to client
                await self.send_to_client(session, response)
            except IgnorePacket:
                continue
            except asyncio.exceptions.TimeoutError:
                log('warning', session=session, message='downstream timed out')
                break
            except timeout:
                log('error', session=session, message='upstream timed out')
                break
            except (ConnectionResetError, ConnectionAbortedError):
                log('warning', session=session, message='downstream disconnected')
                break
            except Exception as e:
                if data is not None:
                    data = data.hex()
                stk = traceback.extract_tb(sys.exc_info()[-1], -1)
                log('exception', session=session, event_raw=data, message=f'{type(e)}:{e} @ {stk}')

        session.close()

    async def handle_request(self, session: Session, request: Frame) -> Frame:
        raise NotImplementedError

    @staticmethod
    def guess_proto(data: bytes) -> str:
        proto_name = 'UNK'

        if data.startswith(b'GET') or data.startswith(b'POST') or data.startswith(b'OPTIONS'):
            proto_name = 'HTTP'
        elif re.match(b'^\x16\x03(\x01|\x02|\x03)', data[:3]):
            proto_name = 'HTTPS'
        elif data.startswith(b'USER ') or data.startswith(b'PASS '):
            proto_name = 'FTP'
        elif data.startswith(b'HELP'):
            proto_name = 'TELNET'

        return proto_name

    def dump_data(self, session: Session, data: bytes, proto_name: str) -> str:
        ts = datetime.now().strftime("%y%m%d-%H%M%S-%f")
        if proto_name is None:
            proto_name = self.guess_proto(data)
            dump_folder = self.other_dump
        else:
            dump_folder = self.winbox_dump

        dump_file = f'{ts}_{session.id}_{proto_name}.bin'
        dump_path = os.path.join(dump_folder, dump_file)
        with open(dump_path, 'wb') as fd:
            fd.write(data)

        log('info', session_id=session.id, message=f'{proto_name} protocol data dumped into {dump_path}')

    def dump_frame(self, session: Session, data: bytes, frame: str) -> None:
        ts = datetime.now().strftime("%y%m%d-%H%M%S-%f")
        dump_folder = self.winbox_dump

        # Data
        dump_file = f'{ts}_{session.id}_data.bin'
        data_path = os.path.join(dump_folder, dump_file)
        with open(data_path, 'wb') as fd:
            fd.write(data)

        # Frame
        dump_file = f'{ts}_{session.id}_frame.json'
        frame_path = os.path.join(dump_folder, dump_file)
        with open(frame_path, 'w') as fd:
            fd.write(frame)

        log('info', session_id=session.id, message=f'Frame dumped into {data_path} and {frame_path}')

    async def recv_from_client(self, session: Session) -> Frame:

        frame = None
        # Reading directly from reader as client is not initialized first time this method is called
        data = await asyncio.wait_for(session.client_reader.read(self.BUFFER_SIZE), timeout=self.TIMEOUT)
        if not data:
            log('warning', session=session, message='No data received')
            return None
        elif len(data) < 2:
            log('warning', session=session, event_raw=data.hex(),
                message='Not enough data received')
            return None

        protocol_name = self.get_winbox_protocol(data)
        self.dump_data(session, data, protocol_name)

        if protocol_name is None:
            log('error', session=session, event_raw=data.hex(),
                message=f'No connection type could be detected with session ID: 0x{data[1]:x}')

            # ! Log hack until we implement DH_MD5 protocol
            if data[1] == 5:
                log('exception', session=session, event_raw=data.hex(),
                    message='Received DH_MD5 connection, but we do not support it, yet. Ignoring packet')
                raise IgnorePacket()
            # If ECSRP5 hasn't been loaded, the flow reaches this code and if ignores the packet to tell the client
            # the server doesn't support this protocol
            elif data[1] == 6:
                log('exception', session=session, event_raw=data.hex(),
                    message='Received ECSRP5 connection, but we do not support it, yet. Ignoring packet')
                raise IgnorePacket()

            return None

        # TODO: detect conn_type changes
        if session.protocol is None:
            log('input', session=session, message=f"New {protocol_name} session")
            session.set_protocol(self.protocols[protocol_name])

        if session.protocol.NEEDS_LOGIN and not session.client.is_logged():
            data = await session.login(data)

        try:
            frame = session.client.deserialize(data)
            self.dump_frame(session, data, str(frame.json()))
            log('input', session=session, event_raw=data.hex(), frame=frame.json())
        except Exception as why:
            log('exception', session=session, event_raw=data.hex(),
                message=f'failed to deserialize request: {why}')

        return frame

    # ? Maybe change it by session.client.send_frame
    async def send_to_client(self, session: Session, frame: Frame):

        log('output', session=session, message='Forwarding frame to client', frame=frame.json())
        await session.client.send_message(frame.message)

    def scan_request(self, session: Session, request: Frame):
        try:
            for detection in self.engine.scan(request):
                log('detection', session=session, message=f'{detection.title} attack detected: {detection.description}')

        except Exception as why:
            log('exception', session=session, message=f'scan failed: {why}')

    def explain_message(self, session: Session, msg: Message) -> Command:

        ret_command = Command.UNKNOWN
        sys_to = msg.get_variable(VariableName.SYS_TO).value
        sys_cmd = msg.get_variable(VariableName.SYS_CMD).value

        # Read file
        if sys_to == [2, 2]:
            if sys_cmd == 1:
                # create file
                str_1 = msg.get_variable('string.1').value
                log('explanation', session=session, message=f'Creating file \'{str_1}\'')
                ret_command = Command.CREATE_FILE
            if sys_cmd == 4:
                # read file
                log('explanation', session=session, message='Read file > Read file')
                ret_command = Command.READ_READ
            if sys_cmd == 5:
                # cancel
                log('explanation', session=session, message='Read file > Cancel')
                ret_command = Command.READ_CANCEL
            if sys_cmd == 7:
                # open for reading no-auth
                str_1 = msg.get_variable('string.1').value
                log('explanation', session=session, message=f'Read file > Open file \'{str_1}\'')
                ret_command = Command.READ_OPEN
        # Login
        elif sys_to == [13, 4]:
            if sys_cmd == 1:
                # login
                log('explanation', session=session, message='Login > Login')
                ret_command = Command.LOGIN_LOGIN
            if sys_cmd == 4:
                # hash request
                log('explanation', session=session, message='Login > Hash request')
                ret_command = Command.LOGIN_HASH_REQ
            if sys_cmd == 7:
                # system info
                log('explanation', session=session, message='Login > System info')
                ret_command = Command.LOGIN_SYS_INFO
        elif sys_to == [72, 1]:
            if sys_cmd == 3:
                str_1 = msg.get_variable('string.1').value
                log('explanation', session=session, message=f'Fileman > Open file \'{str_1}\'')
                ret_command = Command.FILEMAN_OPEN
            if sys_cmd == 4:
                log('explanation', session=session, message='Fileman > Read')
                ret_command = Command.FILEMAN_READ
        elif sys_to == [14]:
            if sys_cmd == 3:
                domain_name = msg.get_variable('string.3').value
                log('explanation', session=session, message=f'DNS request: {domain_name}')
                ret_command = Command.DNS_REQ

        if ret_command == Command.UNKNOWN:
            log('explanation', session=session,
                message=f'Unknown combination. sys_to: {sys_to} sys_cmd: {sys_cmd}')

        return ret_command
