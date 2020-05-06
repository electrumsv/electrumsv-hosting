import asyncio
import base64
from functools import partial
import json
import logging
from typing import Any, Tuple, Dict, Optional

import aiorpcx
import attr
from bitcoinx import hash_to_hex_str, PublicKey, sha256, PrivateKey, int_to_be_bytes, \
    double_sha256, pack_le_uint32
from Cryptodome import Cipher
from Cryptodome.Cipher import AES

from electrumsv_hosting.core.utils import get_nonce, hash_payload, binary_to_hex, int_to_hex
from electrumsv_hosting.core import Header, ClientSession

from client.constants import SERVER_PUBLIC_KEY, ALICE_TEST_ALIAS, \
    ALICE_TEST_IDENTITY_PUBLIC_KEY, ALICE_TEST_IDENTITY_PRIVATE_KEY, BOB_TEST_IDENTITY_PUBLIC_KEY, \
    BOB_TEST_ALIAS


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("example-client")


class PublicClientSession(aiorpcx.RPCSession):
    """public access - no sender signature required - required because a WP42 tunnel cannot be
    established prior to initial registration of an identity pubkey."""

    async def register_identity(self, alias, pubkey) -> str:
        # Todo
        #  1) security challenge - e.g. sign recent timestamp
        #  2) hoarding of aliases

        result = await self.send_request('register_identity', [alias, pubkey])
        logger.debug('register-identity: %s', result)
        return result


class RestrictedClientSession(ClientSession):
    """restricted access - requires sender_signature"""

    def __init__(self, identity_privkey, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.identity_privkey: PrivateKey = identity_privkey
        self.identity_pubkey: PublicKey = identity_privkey.public_key

    def _sign_message(self, sender_pubkey: PublicKey, nonce: bytes, payload_hash: bytes) -> bytes:
        for_signing: str = self.identity_pubkey.to_bytes() + nonce + payload_hash
        signature = self.identity_privkey.sign_message(for_signing)
        return signature

    def _make_header(self, payload: bytes, receiver_pubkey=None, nonce=None):
        nonce = nonce or get_nonce()
        payload_hash = hash_payload(payload)
        signature = self._sign_message(self.identity_pubkey, nonce, payload_hash)
        header = Header(sender_pubkey=self.identity_pubkey, receiver_pubkey=receiver_pubkey,
            sender_nonce=nonce, payload_hash=payload_hash, sender_signature=signature)
        return header

    def _check_header_sig(self, result):
        result_json = json.loads(result)
        header_received = result_json['header']
        signed_message = PublicKey.from_hex(header_received['sender_pubkey']).to_bytes() + \
            bytes.fromhex(header_received['sender_nonce']) + \
            bytes.fromhex(header_received['payload_hash'])

        check_sig_result = SERVER_PUBLIC_KEY.verify_message(
            message_sig=header_received['sender_signature'],
            message=signed_message, hasher=double_sha256)
        if check_sig_result:
            logger.debug("check-message-sig-client: signature check for trusted mailbox_server "
                         "passed")
        else:
            logger.error("check-message-sig-client: signature check for mailbox_server failed!")

    # def _get_derived_keys(self, nonce: bytes, receiver_pubkey: PublicKey) -> Tuple[PrivateKey,
    #         PublicKey]:
    #     nonce_hash = sha256(nonce)  # SHA-256(M)
    #
    #     # Phase II, step 6 WP0042 -> V2C = VMC + SHA-256(M)
    #     private_key2_client = self.identity_privkey.add(nonce_hash)
    #
    #     # Phase II, step 8 WP0042 -> P2S = PMS + SHA-256(M) X G
    #     public_key2_receiver = receiver_pubkey.add(nonce_hash)
    #     return private_key2_client, public_key2_receiver

    def _get_shared_secret(self, receiver_pubkey: PublicKey, nonce: bytes) -> bytes:
        logger.debug("get_shared_secret")
        shared_secret_public_key = self.identity_privkey.shared_secret(receiver_pubkey, nonce)
        return int_to_be_bytes(shared_secret_public_key.to_point()[0])

    def _get_cipher(self, shared_secret_public_key, nonce) -> Cipher:
        cipher = AES.new(shared_secret_public_key, AES.MODE_CTR, nonce=nonce)
        return cipher

    def _make_ciphertext(self, receiver_pubkey: PublicKey, payload: Dict[Any, Any], nonce: bytes):
        """converts json to binary ciphertext"""
        # 1) encode json to utf-8
        payload_bytes = json.dumps(payload).encode("utf-8")

        # 2) encrypt with shared secret
        shared_secret = self._get_shared_secret(receiver_pubkey, nonce)
        cipher = self._get_cipher(shared_secret, nonce)
        return cipher.encrypt(payload_bytes)

    # def send_batch(self, raise_errors=False):
    #     raise NotImplementedError
    #
    # async def handle_request(self, request: core.RequestTypes) -> Any:
    #     raise NotImplementedError

    # ----- Endpoints ----- #
    async def get_identity_key(self, alias: str) -> str:
        logger = logging.getLogger("get-identity-key")
        header = self._make_header(alias.encode('utf-8'))
        response = await self.send_request('get_id_key', [header.to_json(), alias])
        self._check_header_sig(response)
        logger.debug("response=%s", response)
        return response

    async def subscribe_to_messagebox(self, identity_pubkey: PublicKey) -> str:
        logger = logging.getLogger("subscribe-to-messagebox")
        header = self._make_header(identity_pubkey.to_bytes(compressed=True))
        args = [header.to_json(), identity_pubkey.to_hex()]
        response = await self.send_request('subscribe_to_messagebox', args)
        self._check_header_sig(response)
        logger.debug("response=%s", response)
        return response

    async def get_message(self, message_id: int) -> str:
        logger = logging.getLogger("get-message")
        payload = int_to_hex(message_id)
        header = self._make_header(bytes.fromhex(payload))
        args = [header.to_json(), int_to_hex(message_id)]
        response = await self.send_request('subscribe_to_messagebox', args)
        self._check_header_sig(response)
        logger.debug("response=%s", response)
        return response

    async def send_message(self, receiver_pubkey: PublicKey, payload: Dict, message_type: str,
            nonce: Optional[bytes]=None):
        logger = logging.getLogger("send-message")
        logger.debug("sending encrypted message (type='%s') to pubkey=%s", message_type,
            receiver_pubkey)

        nonce = nonce or get_nonce()  # contact_request messages supply landmark nonce
        ciphertext_payload = self._make_ciphertext(receiver_pubkey, payload, nonce)

        # Note: the receiver_pubkey and nonce are actually specified here to link header to payload
        header = self._make_header(ciphertext_payload, receiver_pubkey=receiver_pubkey, nonce=nonce)

        args = [header.to_json(), base64.b64encode(ciphertext_payload).decode()]
        response = await self.send_request('send_message', args)
        self._check_header_sig(response)
        logger.debug("response=%s", response)
        return response

    # ----- P2P / mailbox messages ----- (via `RestrictedClientSession.send_message()`) #
    async def send_contact_request(self, receiver_pubkey: PublicKey):
        """One example usecase of a mailbox message"""
        logger = logging.getLogger("send-contact-request")
        message_type = "contact_request"
        nonce = get_nonce()  # establishes the landmark first nonce for the relationship
        payload = {"message_type": message_type,
                   "did_document": "https://w3c.github.io/did-core/ goes here",
                   "verifiable_credentials": "https://w3c.github.io/vc-data-model/ goes here",
                   "sender_ip": "char[16] / IPv6/4 goes here"}

        logger.debug("send-contact-request: sending payload=%s", payload)
        result = await self.send_message(receiver_pubkey, payload, message_type, nonce=nonce)
        return result

    async def send_contact_response(self, receiver_alias, receiver_pubkey):
        raise NotImplementedError

    async def get_received_contact_requests(self):
        """get personal history of received contact requests"""
        raise NotImplementedError

    async def get_sent_contact_responses(self):
        """get personal history of sent contact responses"""
        raise NotImplementedError


async def main():
    # Connect to public endpoint to register identity pubkey
    async with aiorpcx.connect_rs(host='localhost', port=8889,
            session_factory=PublicClientSession) as session:

        session: PublicClientSession

        alice_pubkey_hex = ALICE_TEST_IDENTITY_PUBLIC_KEY.to_hex()
        register_alice = await session.register_identity(ALICE_TEST_ALIAS, alice_pubkey_hex)

        bob_pubkey_hex = BOB_TEST_IDENTITY_PUBLIC_KEY.to_hex()
        register_bob = await session.register_identity(BOB_TEST_ALIAS, bob_pubkey_hex)

    # Connect via WP42 tunnel for everything else
    session_factory = partial(RestrictedClientSession, ALICE_TEST_IDENTITY_PRIVATE_KEY)
    async with aiorpcx.connect_rs(host='localhost', port=8888, session_factory=session_factory) \
            as session:

        session: RestrictedClientSession
        await session.server_handshake(session.identity_privkey, SERVER_PUBLIC_KEY)
        logger.debug("client_handshake successful")

        alice_identity_pubkey = await session.get_identity_key(alias=ALICE_TEST_ALIAS)

        bob_identity_pubkey = await session.get_identity_key(BOB_TEST_ALIAS)

        result = await session.send_contact_request(receiver_pubkey=BOB_TEST_IDENTITY_PUBLIC_KEY)

asyncio.get_event_loop().run_until_complete(main())
