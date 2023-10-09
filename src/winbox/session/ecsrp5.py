import socket
import asyncio
import secrets
from logger import log
from winbox.message import Message
from winbox.mtcrypto import encryption
from winbox.mtcrypto import elliptic_curves
from winbox.session.session import ClientMgr, UpstreamMgr, InvalidUsername
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1
from Crypto.Util.Padding import pad, unpad
from configparser import SectionProxy

MAGIC = 6
NEEDS_LOGIN = True


class Client(ClientMgr):

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: SectionProxy):
        super().__init__(reader, writer, config)
        self.username = ''
        self.password = ''
        self.stage = 0
        self.w = elliptic_curves.WCurve()
        self.x_w_a = b''
        self.x_w_a_parity = -1
        self.s_b = b''
        self.x_w_b = b''
        self.x_w_b_parity = -1
        self.j = b''
        self.z = b''
        self.secret = b''
        self.client_cc = b''
        self.server_cc = b''
        self.i = b''
        self.x_gamma = b''
        self.gamma_parity = -1
        self.msg = b''
        self.resp = b''
        self.send_aes_key = b''
        self.send_hmac_key = b''
        self.receive_aes_key = b''
        self.receive_hmac_key = b''
        self.parse_userdat(self.config['shared']['users_file'])

    # validates the request user exists in user.dat and retrieves associated salt, x_gamma
    # generates a server public key and formats response
    def public_key_exchange(self, data: bytes):
        nullbyte = data.find(b'\x00')
        self.username = (data[:nullbyte]).decode("utf-8")
        self.x_w_a = data[nullbyte + 1:]
        if not self.check_username():
            raise InvalidUsername(self.username)
        if len(self.x_w_a) != 0x21:
            log('exception', message='invalid client public key length')
            return -1

        self.stage = 1
        self.x_w_a_parity = self.x_w_a[-1]
        self.x_w_a = self.x_w_a[:-1]
        self.server_private = secrets.token_bytes(32)
        self.gen_x_w_b_key()
        self.msg = self.x_w_b + \
            int(self.x_w_b_parity).to_bytes(1, "big") + self.salt
        self.msg = len(self.msg).to_bytes(1, "big") + b'\x06' + self.msg
        return self.msg

    # performs ECPEPKGP-SRP-B to generate a password-entangled public key
    def gen_x_w_b_key(self):
        pub = self.w.multiply_by_g(int.from_bytes(self.server_private, "big"))
        gamma = self.w.redp1(self.x_gamma, 0)
        pt = gamma + pub
        self.x_w_b, self.x_w_b_parity = self.w.to_montgomery(pt)

    # effectively ECPESVDP-SRP-B with a small modification of hashing both public keys together for h
    def gen_shared_secret(self):
        self.i = self.w.gen_password_validator_priv(self.username, self.password, self.salt)
        x_gamma, gamma_parity = self.w.gen_public_key(self.i)
        if self.x_gamma != x_gamma:
            log('exception', message="error calculating password validator input")
            return -1
        self.j = encryption.get_sha2_digest(self.x_w_a + self.x_w_b)
        gamma = self.w.lift_x(int.from_bytes(x_gamma, "big"), 1)
        gamma *= int.from_bytes(self.j, "big")
        w_a = self.w.lift_x(int.from_bytes(
            self.x_w_a, "big"), self.x_w_a_parity)
        pt = gamma + w_a
        pt *= int.from_bytes(self.server_private, "big")
        self.z = self.w.to_montgomery(pt)[0]
        self.secret = encryption.get_sha2_digest(self.z)
        cc = encryption.get_sha2_digest(self.j + self.z)
        if cc != self.client_cc:
            log('exception', message="invalid client cc, check username and password")
            return -1

        self.stage = 2
        self.send_aes_key, self.receive_aes_key, self.send_hmac_key, self.receive_hmac_key = encryption.gen_stream_keys(
            True, self.secret)
        self.server_cc = encryption.get_sha2_digest(self.j + self.client_cc + self.z)
        self.msg = len(self.server_cc).to_bytes(1, "big") + b'\x06' + self.server_cc
        return self.msg

    # performs mac-then-encrypt with the previously computed keys
    # formats response, which is a series of 0xff length messages if len(msg) > 0xff
    # adds modified padding which is similar to PKCS-7
    # def send_message(self, msg: bytes, iv: bytes = b''):
    def encrypt_payload(self, payload: bytes):
        if self.send_aes_key == b'':
            log('exception', message="sending AES key not set, initialize before sending a message")
        if self.send_hmac_key == b'':
            log('exception', message="sending HMAC key not set, initialize before sending a message")
        if payload[0:2] != b'M2':
            log('exception', message="The message should begin with 'M2' and not include the prepended length")
        hmac = HMAC.new(self.send_hmac_key, b'', SHA1)
        hmac.update(payload)
        h = hmac.digest()

        iv = secrets.token_bytes(0x10)
        aes = AES.new(self.send_aes_key, AES.MODE_CBC, iv)
        # modify padding input
        pad_byte = 0xf - len(payload + h) % 0x10
        payload = pad(payload + h + pad_byte.to_bytes(1, "big"), 0x10)
        payload = aes.encrypt(payload)
        payload_len = len(payload)
        payload = payload_len.to_bytes(2, "big") + iv + payload
        if payload_len >= 0xff:
            payload_len = 0xff
        else:
            payload_len += 0x12
        index = b'\x06'
        enc_pl = b''
        while True:
            enc_pl += payload_len.to_bytes(1, "big") + index
            if len(payload) >= 0xff:
                enc_pl += payload[:0xff]
                payload = payload[0xff:]
            else:
                enc_pl += payload
                break
            index = b'\xff'
            if len(payload) >= 0xff:
                payload_len = 0xff
            else:
                payload_len = len(payload)

        return enc_pl

    # reassembles the original encrypted data 0xff chunk by 0xff chunk
    # decrypts with altered padding and validates data using HMAC
    def decrypt_payload(self, payload: bytes):

        assert self.receive_aes_key != b'', \
            log('exception', message="receiving AES key not set, initialize before receiving a message")
        assert self.receive_hmac_key != b'', \
            log('exception', message="receiving HMAC key not set, initialize before receiving a message")
        # assert ct[1] == 6, log('exception',
        #    message="Unknown handler received (expected 0x6), terminating")

        payload = self.extract_payload(payload)
        payload = payload[2:]

        self.resp = b''
        iv = payload[:0x10]
        aes = AES.new(self.receive_aes_key, AES.MODE_CBC, iv)
        self.resp = aes.decrypt(payload[0x10:])
        if self.resp[-1] != 0:
            self.resp = unpad(self.resp, AES.block_size)
        self.resp = self.resp[:-1]
        hmc = self.resp[-20:]
        self.resp = self.resp[:-20]
        hmac = HMAC.new(self.receive_hmac_key, b'', SHA1)
        hmac.update(self.resp)
        assert hmac.digest() == hmc, \
            log('exception', message="Warning, decrypted HMAC failed to authenticate packet data")
        return self.resp

    def extract_payload(self, data: bytes) -> bytes:
        payload = b''

        while True:
            data = data[2:]
            if len(data) >= 0xff:
                payload += data[:0xff]
                data = data[0xff:]
            else:
                payload += data
                break

        return payload

    # performs mac-then-encrypt with the previously computed keys
    # formats response, which is a series of 0xff length messages if len(msg) > 0xff
    # adds modified padding which is similar to PKCS-7
    def send(self, msg: bytes, iv: bytes = b''):
        assert self.send_aes_key != b'', \
            log('exception', message="sending AES key not set, initialize before sending a message")
        assert self.send_hmac_key != b'', \
            log('exception', message="sending HMAC key not set, initialize before sending a message")
        assert msg[0:2] == b'M2', \
            log('exception', message="The message should begin with 'M2' and not include the prepended length")
        hmac = HMAC.new(self.send_hmac_key, b'', SHA1)
        hmac.update(msg)
        h = hmac.digest()
        if iv != b'':
            assert len(iv) == 0x10, log('exception', message="AES CBC IV must be 16 bytes")
        else:
            iv = secrets.token_bytes(0x10)
        aes = AES.new(self.send_aes_key, AES.MODE_CBC, iv)
        # modify padding
        pad_byte = 0xf - len(msg + h) % 0x10
        msg = pad(msg + h + pad_byte.to_bytes(1, "big"), 0x10)
        msg = aes.encrypt(msg)
        msg_len = len(msg)
        msg = msg_len.to_bytes(2, "big") + iv + msg
        if msg_len >= 0xff:
            msg_len = 0xff
        else:
            msg_len += 0x12
        index = b'\x06'
        self.msg = b''
        while True:
            self.msg += msg_len.to_bytes(1, "big") + index
            if len(msg) >= 0xff:
                self.msg += msg[:0xff]
                msg = msg[0xff:]
            else:
                self.msg += msg
                break
            index = b'\xff'
            if len(msg) >= 0xff:
                msg_len = 0xff
            else:
                msg_len = len(msg)
        return self.msg

    # check username dictionary for request username and sets salt, x_gamma, gamma_parity
    def check_username(self):
        log('info', message=f'Trying to log in using \'{self.username}\' username')
        if self.username in self.users:
            self.salt, self.x_gamma = self.users[self.username]
            self.gamma_parity = self.x_gamma[-1]
            self.x_gamma = self.x_gamma[:-1]
            return 1
        return 0

    def is_logged(self):
        return self.stage == 2

    async def login(self, data):

        log('ecsrp5', message="Client is logging in", conn_reader=self.reader)
        while self.stage != 2:
            if data[1] != MAGIC:
                log('exception', message=f"Invalid packet type received by ECSRP5 login method 0x{data[1]:x}",
                    conn_reader=self.reader)
                return None
            data = data[2:]
            if self.stage == 0:  # initial handshake message from client
                log('ecsrp5', message="Exchanging PK with client", conn_reader=self.reader)
                await self.send_raw(self.public_key_exchange(data))
            elif self.stage == 1:  # client confirmation code
                if len(data) != 0x20:
                    log('exception', message="invalid client confirmation code length", conn_reader=self.reader)
                    return None
                self.client_cc = data
                log('ecsrp5', message="Sending shared secret to client", conn_reader=self.reader)
                await self.send_raw(self.gen_shared_secret())

            data = await self.recv_raw()

        log('ecsrp5', message="Client is logged in", conn_reader=self.reader)

        return data

    # parses the /rw/store/user.dat file for usernames, salts, and password validators
    def parse_userdat(self, dat_filepath):
        def get_bytes(msg: bytes, target: bytes):
            if msg.find(target) < 0:
                return -1
            length = msg[msg.find(target) + 4]
            data = msg[msg.find(target) + 5: msg.find(target) + 5 + length]
            return data

        try:
            data = None
            with open(dat_filepath, 'rb') as fd:
                data = fd.read()
        except Exception as e:
            log('exception', message=f'While reading users file: {e}')
        self.users = {}
        while data:
            length = int.from_bytes(data[0:2], "little")
            msg = data[2:length]
            assert msg[0:2] == b"M2", log('exception', message="Incorrect message header")
            username = get_bytes(msg, b"\x01\x00\x00\x21").decode('utf-8')
            salt = get_bytes(msg, b"\x20\x00\x00\x31")
            v = get_bytes(msg, b"\x21\x00\x00\x31")
            if username == -1 or salt == -1 or v == -1:
                return -1
            self.users[username] = [salt, v]
            data = data[length:]

    async def send_message(self, msg: Message):
        await self.send_raw(self.encrypt_payload(msg.serialize()))

    def recv_message(self) -> Message:
        raise NotImplementedError


class Upstream(UpstreamMgr):
    def __init__(self, config: SectionProxy):
        super().__init__(config)
        self.username = config['proxy']['ecsrp5_user']
        self.password = config['proxy']['ecsrp5_password']
        self.stage = -1
        self.w = elliptic_curves.WCurve()
        self.s_a = b''
        self.x_w_a = b''
        self.x_w_a_parity = -1
        self.x_w_b = b''
        self.x_w_b_parity = -1
        self.j = b''
        self.z = b''
        self.secret = b''
        self.client_cc = b''
        self.server_cc = b''
        self.i = b''
        self.msg = b''
        self.resp = b''
        self.send_aes_key = b''
        self.send_hmac_key = b''
        self.receive_aes_key = b''
        self.receive_hmac_key = b''

    # effectively ECPESVDP-SRP-A with a small modification of hashing both public keys together for h
    def gen_shared_secret(self, salt):
        self.i = self.w.gen_password_validator_priv(self.username, self.password, salt)
        x_gamma, gamma_parity = self.w.gen_public_key(self.i)
        v = self.w.redp1(x_gamma, 1)  # parity = 1 inverts the y coordinate result
        w_b = self.w.lift_x(int.from_bytes(self.x_w_b, "big"), self.x_w_b_parity)
        w_b += v
        self.j = encryption.get_sha2_digest(self.x_w_a + self.x_w_b)
        pt = int.from_bytes(self.i, "big") * int.from_bytes(self.j, "big")
        pt += int.from_bytes(self.s_a, "big")
        pt = self.w.finite_field_value(pt)  # mod by curve order to ensure the result is a point within the finite field
        pt = pt * w_b
        self.z, _ = self.w.to_montgomery(pt)
        self.secret = encryption.get_sha2_digest(self.z)

    # performs mac-then-encrypt with the previously computed keys
    # formats response, which is a series of 0xff length messages if len(msg) > 0xff
    # adds modified padding which is similar to PKCS-7
    # def send_message(self, msg: bytes, iv: bytes = b''):
    def encrypt_payload(self, payload: bytes):
        assert self.send_aes_key != b'', log('exception',
                                             message="sending AES key not set, initialize before sending a message")
        assert self.send_hmac_key != b'', log('exception',
                                              message="sending HMAC key not set, initialize before sending a message")
        assert payload[0:2] == b'M2', log('exception',
                                          message="Message should begin with 'M2' and not include the prepended length")
        hmac = HMAC.new(self.send_hmac_key, b'', SHA1)
        hmac.update(payload)
        h = hmac.digest()

        iv = secrets.token_bytes(0x10)
        aes = AES.new(self.send_aes_key, AES.MODE_CBC, iv)
        # modify padding input
        pad_byte = 0xf - len(payload + h) % 0x10
        payload = pad(payload + h + pad_byte.to_bytes(1, "big"), 0x10)
        payload = aes.encrypt(payload)

        payload_len = len(payload)
        payload = payload_len.to_bytes(2, "big") + iv + payload
        if payload_len >= 0xff:
            payload_len = 0xff
        else:
            payload_len += 0x12
        index = b'\x06'
        enc_pl = b''
        while True:
            enc_pl += payload_len.to_bytes(1, "big") + index
            if len(payload) >= 0xff:
                enc_pl += payload[:0xff]
                payload = payload[0xff:]
            else:
                enc_pl += payload
                break
            index = b'\xff'
            if len(payload) >= 0xff:
                payload_len = 0xff
            else:
                payload_len = len(payload)

        return enc_pl

    # reassembles the original encrypted data 0xff chunk by 0xff chunk
    # decrypts with altered padding and validates data using HMAC
    def decrypt_payload(self, data):

        data = self.extract_payload(data)
        ct_assembled = data[2:]
        iv = ct_assembled[:0x10]
        aes = AES.new(self.receive_aes_key, AES.MODE_CBC, iv)
        self.resp = aes.decrypt(ct_assembled[0x10:])
        if self.resp[-1] != 0:
            self.resp = unpad(self.resp, AES.block_size)
        self.resp = self.resp[:-1]
        hmc = self.resp[-20:]
        self.resp = self.resp[:-20]
        hmac = HMAC.new(self.receive_hmac_key, b'', SHA1)
        hmac.update(self.resp)
        assert hmac.digest() == hmc, \
            log('exception', message="Warning, decrypted HMAC failed to authenticate packet data")
        return self.resp

    def extract_payload(self, data: bytes) -> bytes:
        payload = b''

        while True:
            data = data[2:]
            if len(data) >= 0xff:
                payload += data[:0xff]
                data = data[0xff:]
            else:
                payload += data
                break
        # payload = payload[2:]

        return payload

    def open_socket(self):
        super().open_socket()
        self.stage = 0

    # performs authentication in linear manner
    # looped to retry if any errors occur
    def login(self):

        # TODO: Change return codes
        # simple ECPEPKGP-SRP-A algorithm to generate public key
        def public_key_exchange():
            self.s_a = secrets.token_bytes(32)
            self.x_w_a, self.x_w_a_parity = self.w.gen_public_key(self.s_a)
            if not w.check(self.w.lift_x(int.from_bytes(self.x_w_a, "big"), self.x_w_a_parity)):
                self.stage = -1
            self.msg = self.username.encode('utf-8') + b'\x00'
            self.msg += self.x_w_a + int(self.x_w_a_parity).to_bytes(1, "big")
            self.msg = len(self.msg).to_bytes(1, "big") + b'\x06' + self.msg
            self.stage = 1

        # handles server repsonse and performs ECPESVDP-SRP-A to compute z
        # uses z for Cc and formats response to confirm shared secret
        def confirmation():
            resp_len = self.resp[0]
            self.resp = self.resp[2:]
            if len(self.resp) != int(resp_len):
                log('exception', message="Error: challenge response corrupted. Retrying...")
                self.stage = -1
                return
            self.x_w_b = self.resp[:32]
            self.x_w_b_parity = self.resp[32]
            salt = self.resp[33:]
            if len(salt) != 0x10:
                log('exception', message="Error: challenge response corrupted. Retrying...")
                self.stage = -1
                return
            self.gen_shared_secret(salt)
            self.j = encryption.get_sha2_digest(self.x_w_a + self.x_w_b)
            self.client_cc = encryption.get_sha2_digest(self.j + self.z)
            self.msg = len(self.client_cc).to_bytes(1, "big") + b'\x06' + self.client_cc
            self.stage = 2

        w = elliptic_curves.WCurve()

        while True:
            if self.stage == -1:
                if self.socket is not None:
                    self.socket.close()
                self.open_socket()
            elif self.stage == 0:
                public_key_exchange()
            elif self.stage == 1:
                confirmation()
            elif self.stage == 2:
                self.server_cc = encryption.get_sha2_digest(self.j + self.client_cc + self.z)
                if self.resp[2:] != self.server_cc:
                    log('exception', message="Mismatched confirmation key. Retrying..")
                    self.stage = -1
                else:
                    self.stage = 3
            elif self.stage == 3:
                log('upstream', message="Connection successful")
                self.send_aes_key, self.receive_aes_key, self.send_hmac_key, self.receive_hmac_key = \
                    encryption.gen_stream_keys(False, self.secret)
                break

            if self.msg != b'' and self.socket is not None:
                self.socket.send(self.msg)
                self.msg = b''
                try:
                    self.resp = self.socket.recv(1024)
                except socket.timeout:
                    log('exception', message="Error: server timeout. Retrying...")
                    self.stage = -1

        return 0

    # reassembles the original encrypted data 0xff chunk by 0xff chunk
    # decrypts with altered padding and validates data using HMAC
    def receive(self):
        try:
            ct = self.socket.recv(1024)
        except socket.timeout:
            return None
        if self.receive_aes_key == b'':
            log('exception', message="receiving AES key not set, initialize before receiving a message")
        if self.receive_hmac_key == b'':
            log('exception', message="receiving HMAC key not set, initialize before receiving a message")
        assert ct[1] == 6, log('exception', message="Unknown handler received (expected 0x6), terminating")
        self.resp = b''
        ct_assembled = b''
        while True:
            ct = ct[2:]
            if len(ct) >= 0xff:
                ct_assembled += ct[:0xff]
                ct = ct[0xff:]
            else:
                ct_assembled += ct
                break
        ct_assembled = ct_assembled[2:]
        iv = ct_assembled[:0x10]
        aes = AES.new(self.receive_aes_key, AES.MODE_CBC, iv)
        self.resp = aes.decrypt(ct_assembled[0x10:])
        if self.resp[-1] != 0:
            self.resp = unpad(self.resp, AES.block_size)
        self.resp = self.resp[:-1]
        hmc = self.resp[-20:]
        self.resp = self.resp[:-20]
        hmac = HMAC.new(self.receive_hmac_key, b'', SHA1)
        hmac.update(self.resp)
        assert hmac.digest() == hmc, log('exception', message="HMAC failed to authenticate packet data. Exiting")
        return self.resp

    async def send_message(self, msg: Message):
        await self.send_raw(self.encrypt_payload(msg.serialize()))

    def recv_message(self) -> Message:
        raise NotImplementedError

    def payload_joiner(self, data: bytes) -> bytes:
        payload = b''

        while True:
            data = data[2:]
            if len(data) >= 0xff:
                payload += data[:0xff]
                data = data[0xff:]
            else:
                payload += data
                break
        payload = payload[2:]

        return payload
