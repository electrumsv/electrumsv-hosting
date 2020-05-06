import aiorpcx
import bitcoinx
from bitcoinx import PublicKey
import base64
import datetime
import json
import logging
import traceback
from typing import Any, Dict

from electrumsv_hosting.core.utils import get_nonce, binary_to_hex, hash_payload
from electrumsv_hosting.core import Header

from .constants import BOB_TEST_IDENTITY_PUBLIC_KEY, ALICE_TEST_IDENTITY_PUBLIC_KEY, \
    SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY
from .database import Identity, Message
from . import database

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("handlers")


def identity_is_registered(identity_pubkey: PublicKey) -> bool:
    matches = Identity.select().where(Identity.identity_pubkey == identity_pubkey.to_hex())
    if len(matches) == 1:
        return True
    return False


class PublicHandlers:
    """Public access (via plaintext tcp aiorpcx.RPCSession)"""

    def __init__(self):
        self.handlers = {
            'register_identity': self.register_identity
        }

    def get(self, method_name):
        return self.handlers.get(method_name)

    async def register_identity(self, session: Any) -> str:
        logger = logging.getLogger("handlers:register-identity")
        identity_pubkey = session.client_identity_pubkey
        identity_pubkey_hex = identity_pubkey.to_hex()
        if session.account_id is not None:
            return "session account is already registered with '%s'" % identity_pubkey_hex

        account_id = session.app.dbapi.get_account_id_for_identity_pubkey(identity_pubkey)
        if account_id is not None:
            return "'%s' is already registered" % identity_pubkey_hex

        account_id = Identity.insert(identity_pubkey=identity_pubkey_hex).execute()
        logger.debug(f"received identity registration for: '{identity_pubkey_hex}'")

        session.set_account_id(account_id)
        return "identity registration successful for '%s'" % identity_pubkey_hex


class RestrictedHandlers:
    """Access via WP42 tunnel to server only"""

    def __init__(self, server_private_key):
        self.server_private_key = server_private_key
        self.server_public_key = self.server_private_key.public_key
        self.handlers = {
            'subscribe_to_messagebox': self.subscribe_to_messagebox,
            'get_message': self.get_message,
            'send_message': self.send_message
        }

    def get(self, method_name):
        return self.handlers.get(method_name)

    def _check_header_sig(self, header_received):
        logger = logging.getLogger("handlers:_check_header_sig")
        sender_public_key = header_received.sender_pubkey
        signed_message = sender_public_key.to_bytes() + header_received.sender_nonce + \
            header_received.payload_hash

        check_sig_result = sender_public_key.verify_message(
            message_sig=header_received.sender_signature, message=signed_message)
        if check_sig_result:
            logger.debug("signature check for client request passed")
        else:
            logger.error("signature check for client request failed!")

    def _sign_message(self, sender_pubkey: PublicKey, nonce: bytes, payload_hash: bytes) -> bytes:
        logger = logging.getLogger("handlers:_sign_message")

        for_signing: str = self.server_public_key.to_bytes() + nonce + payload_hash
        logger.debug("for signing: %s", for_signing)
        signature = self.server_private_key.sign_message(for_signing)
        return signature

    def _make_header(self, payload: bytes):
        nonce = get_nonce()
        payload_hash = hash_payload(payload)
        signature = self._sign_message(self.server_public_key, nonce, payload_hash)
        header = Header(sender_pubkey=self.server_public_key, receiver_pubkey=None,
                        sender_nonce=nonce, payload_hash=payload_hash, sender_signature=signature)
        return header

    # ----- Endpoints ----- #

    # 1) check received header signature
    # 2) retrieve data from cache/db
    # 3) make response header -> response with header + payload

    async def subscribe_to_messagebox(self, session: Any, header: str) -> str:
        logger = logging.getLogger("handlers:[subscribe-to-messagebox]")
        header_received = Header.from_json(header)
        self._check_header_sig(header_received)

        identity_pubkey = session.client_identity_pubkey
        identity_pubkey_hex = identity_pubkey.to_hex()

        logger.debug(f"received 'subscribe_to_messagebox' request for identity_pubkey: "
            f"'{identity_pubkey_hex}' from client")
        message_id_count = 0  # retrieval not implemented

        payload_bytes = bitcoinx.pack_le_uint32(message_id_count)
        header_response = self._make_header(payload_bytes)
        return json.dumps({"header": header_response.to_dict(),
                           "message_id_count": message_id_count})


    async def get_message(self, header:str, message_id: str) -> str:
        logger = logging.getLogger("handlers:[get-message]")
        header_received = Header.from_json(header)
        self._check_header_sig(header_received)

        logger.debug(f"received 'get_message' request for identity_pubkey: '{identity_pubkey}' "
            f"from client")
        message_id = 0
        message = base64.b64encode("Hello".encode('utf-8')).decode()  # retrieval not implemented

        payload_bytes = bitcoinx.pack_le_uint32(message_id)
        header_response = self._make_header(payload_bytes)
        return json.dumps({"header": header_response.to_dict(),
                           "message_id": message_id,
                           "message": message})

    # One Endpoint for Mailbox messages
    async def send_message(self, session: Any, header: str, encrypted_base64_payload: str) -> str:
        """Stores an encrypted contact_request payload for the given identity pubkey"""
        logger = logging.getLogger("handlers:[send-message]")
        header_received_json = json.loads(header)
        header_received = Header.from_dict(header_received_json)
        self._check_header_sig(header_received)

        logger.debug("header=%s", header)
        logger.debug("encrypted_payload=%s", encrypted_base64_payload)

        # Persist to db
        Message.insert(sender_pubkey=header_received_json['sender_pubkey'],
                       receiver_pubkey=header_received_json['receiver_pubkey'],
                       sender_nonce=header_received.sender_nonce,
                       sender_signature=header_received_json['sender_signature'],
                       date_created=datetime.datetime.now(),
                       payload=base64.b64decode(encrypted_base64_payload)).execute()

        payload_bytes = base64.b64decode(encrypted_base64_payload)
        header_response = self._make_header(payload_bytes)
        return json.dumps({"header": header_response.to_dict(),
                           "status": "message received"})
