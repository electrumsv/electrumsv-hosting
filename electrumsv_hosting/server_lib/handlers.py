import aiorpcx
import bitcoinx
from bitcoinx import PublicKey
import base64
import datetime
import json
import logging
from typing import Dict

from core.utils import get_nonce, binary_to_hex, hash_payload
from core import Header

from .constants import BOB_TEST_ALIAS, BOB_TEST_IDENTITY_PUBLIC_KEY, \
    ALICE_TEST_ALIAS, ALICE_TEST_IDENTITY_PUBLIC_KEY, Errors, SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY
from .database import Alias, Message
from . import database

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("handlers")


def get_pubkey_for_alias(alias) -> PublicKey:
    logger = logging.getLogger("handlers:get_pubkey_for_alias")
    # as a temporary stand-in for an actual database
    try:
        row = Alias.get(Alias.alias == alias)
        return PublicKey.from_hex(row.identity_pubkey)
    except Alias.DoesNotExist as e:
        logger.error(e)
        raise aiorpcx.RPCError(
            Errors.ALIAS_PUBKEY_NOT_FOUND_CODE,
            Errors.ALIAS_PUBKEY_NOT_FOUND_MESSAGE)


def identity_is_registered(alias) -> bool:
    matches = Alias.select().where(Alias.alias == alias)
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

    async def register_identity(self, alias: str, identity_pubkey: str) -> str:
        logger = logging.getLogger("handlers:register-identity")
        """Adds alias and pubkey to Alias table"""
        if identity_is_registered(alias):
            return "identity for '%s' is already registered - choose a different alias" % alias

        Alias.insert(alias=alias, identity_pubkey=identity_pubkey).execute()
        logger.debug(f"received identity registration for: '{alias}'")
        return "identity registration successful for '%s'" % alias


class RestrictedHandlers:
    """Access via WP42 tunnel to server only"""

    def __init__(self, server_private_key):
        self.server_private_key = server_private_key
        self.server_public_key = self.server_private_key.public_key
        self.handlers = {
            'get_id_key': self.get_id_key,
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

    async def get_id_key(self, header: str, alias: str) -> str:
        logger = logging.getLogger("handlers:[get-id-key]")
        header_received = Header.from_json(header)
        self._check_header_sig(header_received)

        logger.debug(f"request for alias: '{alias}' from client")
        identity_pubkey = get_pubkey_for_alias(alias)

        payload_bytes = alias.encode('utf-8')
        header_response = self._make_header(payload_bytes)
        return json.dumps({"header": header_response.to_dict(),
                           "identity_pubkey": identity_pubkey.to_hex()})


    async def subscribe_to_messagebox(self, header: str, identity_pubkey: str) -> str:
        logger = logging.getLogger("handlers:[subscribe-to-messagebox]")
        header_received = Header.from_json(header)
        self._check_header_sig(header_received)

        logger.debug(f"received 'subscribe_to_messagebox' request for identity_pubkey: "
            f"'{identity_pubkey}' from client")
        message_id_count = 0  # retrieval not implemented

        payload_bytes = pack_le_uint32(message_id_count)
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
    async def send_message(self, header: str, encrypted_base64_payload: str) -> str:
        """Stores an encrypted contact_request payload for the given alias"""
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
