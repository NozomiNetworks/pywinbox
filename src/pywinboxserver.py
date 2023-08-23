import os
import asyncio
import ipaddress
import dns.resolver
from dns.resolver import NXDOMAIN
from logger import log
from pywinbox import Pywinbox, Command
from argparse import ArgumentParser
from winbox.error_code import ErrorCode
from winbox.message import Frame, Message
from winbox.session.session import Session, ServerSession
from winbox.variable_name import VariableName
from winbox.variable import BooleanVariable, DwordVariable, DwordVariableArray, RawVariable, StringVariable, \
    Ipv6VariableArray, StringVariableArray


# TODO: Use random salt
SALT = 'b9ae04361df9ea45c070215501a5addd'


class PywinboxServer(Pywinbox):

    def __init__(self, config_path: str):
        super().__init__(config_path)
        self.ip = self.config['server']['host']
        self.port = self.config['server']['port']
        log('control', message=f'Starting Pywinbox server listening on {self.ip}:{self.port}')

    def new_session(self, reader, writer,) -> Session:
        return ServerSession(reader, writer, self.config)

    async def handle_request(self, session: Session, request: Frame) -> Frame:

        response = None
        mock_functions = {
            Command.UNKNOWN: self.mock_insufficient_permissions_error,
            Command.READ_OPEN: self.mock_read_open,
            Command.READ_READ: self.mock_read_read,
            Command.READ_CANCEL: self.mock_read_cancel,
            Command.LOGIN_LOGIN: self.mock_login_login,
            Command.LOGIN_HASH_REQ: self.mock_login_hash_req,
            Command.LOGIN_SYS_INFO: self.mock_login_sys_info,
            Command.CREATE_FILE: self.mock_create_file,
            Command.FILEMAN_OPEN: self.mock_read_open,  # They seem to work in the same way
            Command.FILEMAN_READ: self.mock_read_read,  # They seem to work in the same way
            Command.DNS_REQ: self.mock_dns_request,
        }

        command = self.explain_message(session, request.message)
        response = mock_functions[command](session, request.message)
        session.stdid += 1

        return response

    def gen_error_msg(self, msg: Message, error: ErrorCode) -> Frame:

        response = Frame(answer_to=msg)
        response.message.add_variable(DwordVariable(VariableName.SYS_ERRNO, error.value))
        response.message.add_variable(DwordVariable(VariableName.SYS_REQID,
                                                    msg.get_variable(VariableName.SYS_REQID).value))

        return response

    # Mocking methods #

    # Parser for Command.UNKNOWN
    def mock_insufficient_permissions_error(self, session: ServerSession, msg: Message) -> Frame:
        response = self.gen_error_msg(msg, ErrorCode.NOT_PERMITTED)
        log('unexpected', session_id=session.id, frame=msg.json())

        return response

    # Parser for Command.READ_OPEN and Command.FILEMAN_OPEN
    def mock_read_open(self, session: ServerSession, msg: Message) -> Frame:
        response = Frame(answer_to=msg)

        file_path = msg.get_variable('string.1').value
        file_length = self.open_file(session, file_path)
        if file_length is None:
            log('unexpected', session_id=session.id, frame=msg.json(),
                message=f'Trying to open nonexistent file {file_path}')
            return self.gen_error_msg(msg, ErrorCode.NOT_PERMITTED)

        response.message.add_variable(DwordVariable(VariableName.STD_ID, session.stdid))
        response.message.add_variable(DwordVariable(VariableName.SYS_TYPE, 2))
        response.message.add_variable(DwordVariable(2, file_length))  # file length
        response.message.add_variable(DwordVariable(VariableName.SYS_REQID,
                                                    msg.get_variable(VariableName.SYS_REQID).value))

        return response

    # Parser for Command.READ_READ and Command.FILEMAN_READ
    def mock_read_read(self, session: ServerSession, msg: Message) -> Frame:
        response = Frame(answer_to=msg)

        data = self.read_file(session)

        response.message.add_variable(DwordVariable(VariableName.SYS_TYPE, 2))
        response.message.add_variable(DwordVariable(VariableName.SYS_REQID,
                                                    msg.get_variable(VariableName.SYS_REQID).value))
        response.message.add_variable(RawVariable(3, data))

        return response

    # Parser for Command.READ_CANCEL
    def mock_read_cancel(self, session: ServerSession, msg: Message) -> Frame:
        response = Frame(answer_to=msg)

        return response

    # Parser for Command.LOGIN_LOGIN
    def mock_login_login(self, session: ServerSession, msg: Message) -> Frame:
        response = Frame(answer_to=msg)

        return response

    # Parser for Command.LOGIN_HASH_REQ
    def mock_login_hash_req(self, session: Session, msg: Message):
        response = Frame(answer_to=msg)

        response.message.add_variable(DwordVariable(VariableName.SYS_TYPE, 2))
        response.message.add_variable(DwordVariable(VariableName.SYS_REQID,
                                                    msg.get_variable(VariableName.SYS_REQID).value))
        response.message.add_variable(RawVariable(9, bytearray.fromhex(SALT)))

        return response

    # Parser for Command.LOGIN_SYS_INFO
    def mock_login_sys_info(self, session: Session, msg: Message):
        response = Frame(answer_to=msg)

        response.message.add_variable(DwordVariable(VariableName.SYS_TYPE, 2))
        response.message.add_variable(DwordVariable(VariableName.SYS_REQID,
                                                    msg.get_variable(VariableName.SYS_REQID).value))
        response.message.add_variable(BooleanVariable(38, False))
        response.message.add_variable(BooleanVariable(28, False))
        response.message.add_variable(BooleanVariable(19, False))
        response.message.add_variable(DwordVariable(15, 0))
        response.message.add_variable(DwordVariable(16, 0))
        response.message.add_variable(DwordVariable(11, 0x5fffe))
        response.message.add_variable(StringVariable(22, "3.30"))
        response.message.add_variable(StringVariable(23, "x86"))
        response.message.add_variable(StringVariable(21, "x86"))
        response.message.add_variable(StringVariable(17, "i386"))

        return response

    # Parser for Command.DNS_REQ
    def mock_dns_request(self, session: Session, msg: Message):
        response = Frame(answer_to=msg)

        domain_name = msg.get_variable('string.3').value
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8']

        try:
            answer = resolver.resolve(domain_name)
        except NXDOMAIN:
            log('unexpected', session_id=session.id, frame=msg.json(),
                message=f'Trying to resolve nonexistent domain {domain_name}')
            return self.gen_error_msg(msg, ErrorCode.TIMEOUT)

        ip_addr = answer[0].address
        rev_ip = '.'.join(ip_addr.split('.')[::-1])
        int_ip = int(ipaddress.ip_address(rev_ip))  # convert IP to int

        response.message.add_variable(DwordVariableArray(7, [8155]))
        response.message.add_variable(Ipv6VariableArray(11, []))
        response.message.add_variable(DwordVariableArray(6, [int_ip]))
        response.message.add_variable(StringVariableArray(5, [domain_name]))
        response.message.add_variable(DwordVariable(4, int_ip))
        response.message.add_variable(DwordVariable(VariableName.SYS_TYPE, 2))
        response.message.add_variable(DwordVariable(VariableName.SYS_REQID,
                                                    msg.get_variable(VariableName.SYS_REQID).value))
        response.message.add_variable(StringVariable(3, domain_name))

        return response

    # Parser for Command.CREATE_FILE
    def mock_create_file(self, session: Session, msg: Message):
        response = Frame(answer_to=msg)

        file_path = msg.get_variable('string.1').value
        # session.opened_file = file_path
        self.create_file(session, file_path)

        response.message.add_variable(DwordVariable(VariableName.STD_ID, session.stdid))
        response.message.add_variable(DwordVariable(VariableName.SYS_TYPE, 2))
        response.message.add_variable(DwordVariable(VariableName.SYS_REQID,
                                                    msg.get_variable(VariableName.SYS_REQID).value))

        return response

    # Mocking support methods #

    def open_file(self, session: ServerSession, path: str) -> int:
        path = os.path.normpath(path)
        session.opened_file = path
        log('sandbox', session=session, message=f'Trying to open file \'{path}\'')
        return self.get_file_length(session, path)

    def get_file_length(self, session: ServerSession, path: str) -> int:
        # TODO: Implement/add virtual FS
        file_len = None
        path = os.path.normpath(path)
        if path.startswith('//'):
            path = path[1:]
        if path in session.fs:
            file_len = len(session.fs[path])

        return file_len

    def create_file(self, session: ServerSession, path: str):
        # ! Virtual FS mockup
        path = os.path.normpath(path)
        if path.startswith('//'):
            path = path[1:]
        if path not in session.fs:
            session.fs[path] = ""

    def read_file(self, session: Session) -> bytes:

        data = session.fs.get(session.opened_file, b'')

        return data


if __name__ == "__main__":
    parser = ArgumentParser()
    # parser.add_argument("mode", help="Working mode", choices=['server', 'proxy'])
    parser.add_argument("--config", help="Alternative configuration file path")
    args = parser.parse_args()

    if args.config:
        config_path = args.config
    else:
        config_path = 'config.ini'

    asyncio.run(PywinboxServer(config_path).run())
