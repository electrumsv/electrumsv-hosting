import asyncio
import logging
from pprint import pprint
import traceback
from typing import Any, Optional

import aiorpcx
from bitcoinx import int_to_be_bytes, PrivateKey, PublicKey

from electrumsv_hosting import core


logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger("example-server")


client_public_key = PublicKey.from_hex(
    '02ac467548c30f053388350da5a0a4aabaf9df03ac2180a01aecff1c8b9a0ea493')

server_private_key_bytes = bytes.fromhex(
    '6feba37e2c41c1caf6a2e6ee45e432da43d5eb34b61951df2833fe47bfbf65af')
server_private_key = PrivateKey(server_private_key_bytes)



# Handlers are declared as normal python functions.  aiorpcx automatically checks RPC
# arguments, including named arguments, and returns errors as appropriate
async def handle_echo(message: str) -> str:
    logger.debug(f"received echo '{message}' from client")
    return f"{message}+server"

async def handle_sum(*values):
    return sum(values, 0)


handlers = {
    'echo': handle_echo,
    'sum': handle_sum,
}




class ServerSession(core.ServerSession):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        logger.debug(f'connection from {self.remote_address()}')

    async def connection_lost(self):
        await super().connection_lost()
        logger.debug(f'{self.remote_address()} disconnected')

    async def handle_request(self, request: core.RequestTypes) -> Any:
        if isinstance(request, core.HandshakeNotification):
            return None

        logger.debug("handle_request")
        handler = handlers.get(request.method)
        coro = aiorpcx.handler_invocation(handler, request)()
        return await coro

    async def validate_client_identity(self, public_key: PublicKey) -> Optional[int]:
        logger.debug("validate_client_identity %s %s",
            public_key.to_hex(), client_public_key.to_hex())
        if public_key != client_public_key:
            return None
        logger.debug("validate_client_identity.match")
        return 1

    async def get_shared_secret(self, account_id: int, client_identity_public_key: PublicKey,
            message_bytes: bytes) -> bytes:
        logger.debug("get_shared_secret")
        shared_secret_public_key = server_private_key.shared_secret(client_identity_public_key,
            message_bytes)
        return int_to_be_bytes(shared_secret_public_key.to_point()[0])


def loop_exception_handler(loop, context) -> None:
    logger.debug('Exception handler called')
    logger.debug(context)

async def wakeup():
    while True:
        await asyncio.sleep(0.2)

loop = asyncio.get_event_loop()
loop.set_exception_handler(loop_exception_handler)
server = loop.run_until_complete(aiorpcx.serve_rs(ServerSession, 'localhost', 8888))
loop.create_task(wakeup())
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

