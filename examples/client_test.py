import asyncio
import logging
import os

import aiorpcx
from bitcoinx import PrivateKey, PublicKey

from electrumsv_hosting.core import ClientSession

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


async def main(host, port):
    session: ClientSession
    async with aiorpcx.connect_rs(host, port, session_factory=ClientSession) as session:
        await session.server_handshake(client_id_private_key, server_public_key)
        logger.debug("client_handshake")

        # A good request with standard argument passing
        result = await session.send_request('echo', ["Howdy"+"+client"])
        logger.debug("received echo from server '%s'", result)


asyncio.get_event_loop().run_until_complete(main('localhost', 8888))
