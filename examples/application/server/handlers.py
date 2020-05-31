import base64
import datetime
import functools
import json
import logging
import traceback
from typing import Any, Callable, Dict, Optional, TYPE_CHECKING

import aiorpcx
import bitcoinx
from bitcoinx import PrivateKey, PublicKey

from electrumsv_hosting.connection import Header, Message, HandshakeNotification
from electrumsv_hosting.messagebox import (GetMessageRequest, GetMessageResponse, MessageType,
    RegisterIdentityRequest, RegisterIdentityResponse, SendMessageRequest, SendMessageResponse,
    SubscriptionRequest, SubscriptionResponse)
from electrumsv_hosting.utils import get_nonce, binary_to_hex, hash_payload

from .constants import BOB_TEST_IDENTITY_PUBLIC_KEY, ALICE_TEST_IDENTITY_PUBLIC_KEY, \
    SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY
from . import database

if TYPE_CHECKING:
    from .session import IncomingClientSession


def register_message_handler(message_type: MessageType):
    class Decorator:
        def __init__(self, fn):
            self.fn = fn
        def __set_name__(self, klass: 'BaseAPI', name: str) -> None:
            setattr(klass, name, self.fn)
            klass.handlers[message_type] = name
    return Decorator


class APIException(Exception):
    pass


APIHandlerSignature = Callable[[Message],Optional[Message]]


class BaseAPI:
    handlers: Dict[MessageType, str] = {}

    async def dispatch_message(self, message: Message) -> Optional[Message]:
        handler_name = self.handlers.get(message.message_type)
        if handler_name is None:
            raise APIException("Handler not found")
        handler: APIHandlerSignature = getattr(self, handler_name)
        return await handler(message)


class PublicAPI(BaseAPI):
    def __init__(self) -> None:
        super().__init__()

        self._logger = logging.getLogger("api-public")

    @register_message_handler(MessageType.HANDSHAKE_REQUEST)
    async def connection_handshake(self, session: 'IncomingClientSession',
            message: HandshakeNotification) -> None:
        await session.on_handshake(message.identity_public_key)
        return None

    @register_message_handler(MessageType.REGISTER_IDENTITY_REQUEST)
    async def register_identity(self, session: 'IncomingClientSession',
            message: RegisterIdentityRequest) -> RegisterIdentityResponse:
        if session.client_identity_id is not None:
            raise APIException("session already registered")

        identity_pubkey = session.client_identity_pubkey
        identity_id = session.app.dbapi.get_id_for_identity(identity_pubkey)
        if identity_id is not None:
            raise APIException("identity key already registered")

        identity_id = session.app.dbapi.create_identity(identity_pubkey)
        self._logger.debug("register_identity key=%s id=%d", identity_pubkey.to_hex(), identity_id)

        session.on_register_identity(identity_id)
        return RegisterIdentityResponse()


class RestrictedAPI(BaseAPI):
    """Access via WP42 tunnel to server only"""

    def __init__(self) -> None:
        super().__init__()

        self._logger = logging.getLogger("api-private")

    # def _check_header_sig(self, header_received):
    #     sender_public_key = header_received.sender_pubkey
    #     signed_message = sender_public_key.to_bytes() + header_received.sender_nonce + \
    #         header_received.payload_hash

    #     check_sig_result = sender_public_key.verify_message(
    #         message_sig=header_received.sender_signature, message=signed_message)
    #     if check_sig_result:
    #         self._logger.debug("signature check for client request passed")
    #     else:
    #         self._logger.error("signature check for client request failed!")

    @register_message_handler(MessageType.SUBSCRIPTION_REQUEST)
    async def subscribe_to_messagebox(self, session: 'IncomingClientSession',
            message: SubscriptionRequest) -> SubscriptionResponse:
        identity_pubkey = session.client_identity_pubkey
        self._logger.debug("received 'subscribe_to_messagebox' request for identity_pubkey: "
            "'%s' from client", identity_pubkey.to_hex())
        latest_message_id = session.app.dbapi.get_latest_message_id(session.client_identity_id)
        return SubscriptionResponse(latest_message_id)

    @register_message_handler(MessageType.GET_MESSAGE_REQUEST)
    async def get_message(self, session: 'IncomingClientSession', message: GetMessageRequest) \
            -> GetMessageResponse:
        identity_pubkey = session.client_identity_pubkey
        self._logger.debug("received 'get_message' request for identity_pubkey: '%s' from client",
            identity_pubkey.to_hex())
        m = session.app.dbapi.get_message(session.client_identity_id, message.message_id)
        sender_pubkey = PublicKey.from_hex(m.identity.identity_pubkey)
        receiver_pubkey = PublicKey.from_hex(m.receiver_pubkey)
        header = Header(sender_pubkey, receiver_pubkey, m.sender_nonce, m.payload_hash,
            m.sender_signature)
        return GetMessageResponse(header, m.payload)

    @register_message_handler(MessageType.SEND_MESSAGE_REQUEST)
    async def send_message(self, session: 'IncomingClientSession', message: SendMessageRequest) \
            -> SendMessageResponse:
        # Check signature.


        self._logger.debug("header=%s", header)
        self._logger.debug("encrypted_payload=%s", encrypted_base64_payload)

        # Persist to db
        MessageModel.insert(sender_pubkey=header_received_json['sender_pubkey'],
                       receiver_pubkey=header_received_json['receiver_pubkey'],
                       sender_nonce=header_received.sender_nonce,
                       sender_signature=header_received_json['sender_signature'],
                       date_created=datetime.datetime.now(),
                       payload=base64.b64decode(encrypted_base64_payload)).execute()

        payload_bytes = base64.b64decode(encrypted_base64_payload)
        header_response = self._make_header(payload_bytes)
        return json.dumps({"header": header_response.to_dict(),
                           "status": "message received"})
