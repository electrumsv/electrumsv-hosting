import asyncio
import logging
from typing import Any, cast, Optional

import aiorpcx
from bitcoinx import int_to_be_bytes, PrivateKey, PublicKey

from electrumsv_hosting.connection import HandshakeNotification, Message, ServerSession
from electrumsv_hosting.constants import CODE_ERROR, HANDSHAKE_MESSAGE_TYPE

from messages import (EchoMessageRequest, EchoMessageResponse, MessageType, SumMessageRequest,
    SumMessageResponse)


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


class BasicServerSession(ServerSession):
    def __init__(self, transport, *, loop=None, connection=None):
        super().__init__(transport, loop=loop, connection=connection)
        logger.debug("connected: %s", self.remote_address())

    async def connection_lost(self) -> None:
        await super().connection_lost()
        logger.debug("disconnected: %s", self.remote_address())

    async def handle_message(self, message: Message) -> Any:
        logger.debug("handle_message %s", message)

        if message.message_type == HANDSHAKE_MESSAGE_TYPE:
            return None

        if message.message_type == MessageType.SUM_REQUEST:
            sum_request = cast(SumMessageRequest, message)
            summed_value = await handle_sum(sum_request.l_value, sum_request.r_value)
            return SumMessageResponse(summed_value)
        elif message.message_type == MessageType.ECHO_REQUEST:
            echo_request = cast(EchoMessageRequest, message)
            echoed_text = await handle_echo(echo_request.data.decode())
            return EchoMessageResponse(echoed_text.encode())

        raise aiorpcx.RPCError(CODE_ERROR, f'bad message "{message.message_type}"')

    async def get_shared_secret(self, client_public_key: PublicKey, message_bytes: bytes) -> bytes:
        logger.debug("get_shared_secret")
        shared_secret_public_key = server_private_key.shared_secret(client_public_key,
            message_bytes)
        return int_to_be_bytes(shared_secret_public_key.to_point()[0])


def loop_exception_handler(loop, context) -> None:
    logger.debug('Exception handler called')
    logger.debug(context)

async def wakeup() -> None:
    while True:
        await asyncio.sleep(0.2)

loop = asyncio.get_event_loop()
loop.set_exception_handler(loop_exception_handler)
server = loop.run_until_complete(aiorpcx.serve_rs(BasicServerSession, 'localhost', 8888))
loop.create_task(wakeup())
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

