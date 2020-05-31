import asyncio
import logging

import aiorpcx
from bitcoinx import int_to_be_bytes, PrivateKey, PublicKey

from electrumsv_hosting.connection import ClientSession

from messages import (EchoMessageRequest, EchoMessageResponse, MessageType, SumMessageRequest,
    SumMessageResponse)


logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger("example-client")


client_id_private_key_bytes = bytes.fromhex(
    'cccb15a3adddb038a4bb35308741b00f97f56aa9c8c166b93f2c05a6248ee1cb')
client_id_private_key = PrivateKey(client_id_private_key_bytes)
client_id_public_key = client_id_private_key.public_key

server_private_key_bytes = bytes.fromhex(
    '6feba37e2c41c1caf6a2e6ee45e432da43d5eb34b61951df2833fe47bfbf65af')
server_private_key = PrivateKey(server_private_key_bytes)
server_public_key = server_private_key.public_key


class BasicClientSession(ClientSession):
    async def get_shared_secret(self, remote_public_key: PublicKey, message_bytes: bytes) -> bytes:
        shared_secret_public_key = client_id_private_key.shared_secret(remote_public_key,
            message_bytes)
        return int_to_be_bytes(shared_secret_public_key.to_point()[0])


async def main(host, port):
    session: BasicClientSession
    async with aiorpcx.connect_rs(host, port, session_factory=BasicClientSession) as session:
        await session.server_handshake(client_id_private_key, server_public_key)
        logger.debug("client_handshake")

        # A good request with standard argument passing
        message = EchoMessageRequest("Howdy+client".encode())
        result = await session.send_request(message)
        logger.debug("received echo from server '%s'", result.data.decode())


asyncio.get_event_loop().run_until_complete(main('localhost', 8888))
