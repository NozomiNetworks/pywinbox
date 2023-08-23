import asyncio
from logger import log
from pywinbox import Pywinbox
from winbox.message import Frame
from winbox.session.session import Session, ProxySession
from argparse import ArgumentParser


class PywinboxProxy(Pywinbox):

    def __init__(self, config_path: str):
        super().__init__(config_path)
        self.ip = self.config['proxy']['host']
        self.port = self.config['proxy']['port']
        log('control', message=f'Starting Pywinbox proxy listening on {self.ip}:{self.port}')

    def new_session(self, reader, writer) -> Session:
        return ProxySession(reader, writer, self.config)

    async def handle_request(self, session: Session, request: Frame) -> Frame:

        self.explain_message(session, request.message)

        # Send frame to server
        # log('upstream', session=session, message='Forwarding frame to upstream', frame=request.json())
        await session.upstream.send_message(request.message)

        # Receive frame from server
        try:
            data = await session.upstream.recv_raw()
            response = session.upstream.deserialize(data)
            # log('upstream', session=session, event_raw=data.hex(), frame=response.json(), host=session.upstream.host,
            #    message='Received answer from upstream')

        except Exception as why:
            log('exception', session=session, event_raw=data.hex(), host=session.upstream.host,
                message=f'failed to deserialize response: {why}')

        return response


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--config", help="Alternative configuration file path")
    args = parser.parse_args()

    if args.config:
        config_path = args.config
    else:
        config_path = 'config.ini'

    asyncio.run(PywinboxProxy(config_path).run())
