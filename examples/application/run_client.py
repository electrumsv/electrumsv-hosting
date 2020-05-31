import asyncio
import base64
from functools import partial
import json
import logging
from typing import Any, Tuple, Dict, Optional

import aiorpcx
from bitcoinx import hash_to_hex_str, PublicKey, sha256, PrivateKey, int_to_be_bytes, \
    double_sha256, pack_le_uint32
from Cryptodome import Cipher
from Cryptodome.Cipher import AES

from electrumsv_hosting.connection import Header, ClientSession
from electrumsv_hosting.utils import get_nonce, hash_payload, binary_to_hex, int_to_hex
from electrumsv_hosting.messagebox import (GetMessageRequest, GetMessageResponse,
    MessageHeader, RegisterIdentityRequest, RegisterIdentityResponse, SendMessageRequest,
    SendMessageResponse, SubscriptionRequest)

from client.constants import SERVER_PUBLIC_KEY, ALICE_TEST_IDENTITY_PUBLIC_KEY, \
    ALICE_TEST_IDENTITY_PRIVATE_KEY, BOB_TEST_IDENTITY_PUBLIC_KEY, \
    BOB_TEST_IDENTITY_PRIVATE_KEY


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("example-client")


class PublicClientSession(aiorpcx.RPCSession):
    """public access - no sender signature required - required because a WP42 tunnel cannot be
    established prior to initial registration of an identity pubkey."""



class RestrictedClientSession(ClientSession):
    """restricted access - requires sender_signature"""

    def __init__(self, identity_privkey, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.identity_privkey: PrivateKey = identity_privkey
        self.identity_pubkey: PublicKey = identity_privkey.public_key

    async def register_identity(self) -> str:
        message = RegisterIdentityRequest()
        result: RegisterIdentityResponse = await self.send_request(message)
        logger.debug('register-identity: %s', result)
        return result

    def _sign_message(self, sender_pubkey: PublicKey, nonce: bytes, payload_hash: bytes) -> bytes:
        for_signing: str = self.identity_pubkey.to_bytes() + nonce + payload_hash
        signature = self.identity_privkey.sign_message(for_signing)
        return signature

    # def _check_header_sig(self, header: MessageHeader):
    #     result_json = json.loads(result)
    #     header_received = result_json['header']
    #     signed_message = PublicKey.from_hex(header_received['sender_pubkey']).to_bytes() + \
    #         bytes.fromhex(header_received['sender_nonce']) + \
    #         bytes.fromhex(header_received['payload_hash'])

    #     check_sig_result = SERVER_PUBLIC_KEY.verify_message(
    #         message_sig=header_received['sender_signature'],
    #         message=signed_message, hasher=double_sha256)
    #     if check_sig_result:
    #         logger.debug("check-message-sig-client: signature check for trusted mailbox_server "
    #                      "passed")
    #     else:
    #         logger.error("check-message-sig-client: signature check for mailbox_server failed!")

    def get_shared_secret(self, receiver_pubkey: PublicKey, nonce: bytes) -> bytes:
        logger.debug("get_shared_secret")
        shared_secret_public_key = self.identity_privkey.shared_secret(receiver_pubkey, nonce)
        return int_to_be_bytes(shared_secret_public_key.to_point()[0])

    # ----- Endpoints ----- #
    async def subscribe_to_messagebox(self) -> str:
        logger = logging.getLogger("subscribe-to-messagebox")
        response = await self.send_request(SubscriptionRequest())
        logger.debug("response=%s", response)
        return response

    async def get_message(self, message_id: int) -> GetMessageResponse:
        logger = logging.getLogger("get-message")
        response: GetMessageResponse = await self.send_request(GetMessageRequest(message_id))
        logger.debug("response=%s", response)
        return response

    async def send_message(self, receiver_pubkey: PublicKey, payload: bytes, message_type: str,
            nonce: Optional[bytes]=None) -> SendMessageResponse:
        logger = logging.getLogger("send-message")
        logger.debug("sending encrypted message (type='%s') to pubkey=%s", message_type,
            receiver_pubkey)

        nonce = nonce or get_nonce()
        payload_hash = hash_payload(payload)
        signature = self._sign_message(self.identity_pubkey, nonce, payload_hash)
        header = MessageHeader(self.identity_pubkey, receiver_pubkey, nonce, payload_hash,
            signature)
        message = SendMessageRequest(header, payload)
        response: SendMessageResponse = await self.send_request(message)
        assert isinstance(response, SendMessageResponse)
        logger.debug("response=%s", response)
        return response

async def main():
    # Connect to public endpoint to register identity pubkey
    # async with aiorpcx.connect_rs(host='localhost', port=8889,
    #         session_factory=PublicClientSession) as session:

    #     session: PublicClientSession


    #     bob_pubkey_hex = BOB_TEST_IDENTITY_PUBLIC_KEY.to_hex()
    #     register_bob = await session.register_identity(bob_pubkey_hex)

    # Connect via WP42 tunnel for everything else

    # Register Alice.
    session_factory = partial(RestrictedClientSession, ALICE_TEST_IDENTITY_PRIVATE_KEY)
    async with aiorpcx.connect_rs(host='localhost', port=8888, session_factory=session_factory) \
            as session:

        session: RestrictedClientSession
        await session.server_handshake(session.identity_privkey, SERVER_PUBLIC_KEY)
        logger.debug("client_handshake successful for Alice")

        _register_alice = await session.register_identity()
        logger.debug("registered Alice")

    session_factory = partial(RestrictedClientSession, BOB_TEST_IDENTITY_PRIVATE_KEY)
    async with aiorpcx.connect_rs(host='localhost', port=8888, session_factory=session_factory) \
            as session:

        session: RestrictedClientSession
        await session.server_handshake(session.identity_privkey, SERVER_PUBLIC_KEY)
        logger.debug("client_handshake successful for Bob")

        _register_bob = await session.register_identity()
        logger.debug("registered Bob")

        message_type = "custom_message_type"
        payload = {"message_type": message_type,
                   "message": "Bob's secret p2p message to Alice"}
        _response = await session.send_message(receiver_pubkey=ALICE_TEST_IDENTITY_PUBLIC_KEY,
            payload=payload, message_type=message_type)

    # session_factory = partial(RestrictedClientSession, ALICE_TEST_IDENTITY_PRIVATE_KEY)
    # async with aiorpcx.connect_rs(host='localhost', port=8888, session_factory=session_factory) \
    #         as session:

    #     session: RestrictedClientSession
    #     await session.server_handshake(session.identity_privkey, SERVER_PUBLIC_KEY)
    #     logger.debug("client_handshake successful for Alice")

    #     a = await session.subscribe_to_messagebox()

    #     response = await session.get_message()

    #     message_type = "custom_message_type"
    #     payload = {"message_type": message_type,
    #                "message": "Bob's secret p2p message to Alice"}
    #     response = await session.send_message(receiver_pubkey=ALICE_TEST_IDENTITY_PRIVATE_KEY,
    #         payload=payload, message_type=message_type)


asyncio.get_event_loop().run_until_complete(main())
