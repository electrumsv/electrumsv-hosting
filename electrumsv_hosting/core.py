import enum
import logging
import os
from functools import partial
import struct
import time
import traceback
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

import asyncio
import aiorpcx
import aiorpcx.framing
from bitcoinx import int_to_be_bytes, PrivateKey, PublicKey, sha256
import cbor2
from Cryptodome.Cipher import AES, _mode_ctr


logger = logging.getLogger("esvhosting-core")

PROTOCOL_VERSION = 1
HANDSHAKE_LENGTH = 4 + 33 + 12 + 65
HANDSHAKE_TIMESTAMP_VARIANCE = 5

class ErrorCodes(enum.IntEnum):
    INVALID_CLIENT_IDENTITY = 20000
    INVALID_CLIENT_SIGNATURE = 20001
    INVALID_CLIENT_TIMESTAMP = 20002
    INVALID_CLIENT_VERSION = 20003


class ConnectionNotEstablishedError(Exception):
    pass

class ConnectionError(Exception):
    pass


# These exceptions happen in the aiorpcx RPCSession `_process_messages` message processing.
class AuthenticationError(aiorpcx.ProtocolError):
    pass


FrameableType = Union[bytes, Dict[str, Any]]

class BaseFramer:
    _incoming_cipher: Optional[_mode_ctr.CtrMode] = None
    _outgoing_cipher: Optional[_mode_ctr.CtrMode] = None

    def __init__(self) -> None:
        self.byte_queue = aiorpcx.framing.ByteQueue()
        self.received_bytes = self.byte_queue.put_nowait
        self.fail = self.byte_queue.fail

    def frame(self, data: FrameableType) -> bytes:
        if isinstance(data, bytes):
            return data

        message_bytes = cbor2.dumps(data)
        encypted_message_bytes = self._outgoing_cipher.encrypt(message_bytes)
        return b''.join((
            struct.pack("<I", len(encypted_message_bytes)),
            encypted_message_bytes,
        ))

    async def receive_message(self) -> Dict[str, Any]:
        message_length_bytes = await self.byte_queue.receive(4)
        message_length = struct.unpack("<I", message_length_bytes)[0]

        encypted_message_bytes = await self.byte_queue.receive(message_length)
        message_bytes = self._incoming_cipher.decrypt(encypted_message_bytes)
        return cbor2.loads(message_bytes)

    def _get_timestamp(self) -> int:
        return int(time.time())


class ClientFramer(BaseFramer):
    def frame_handshake(self, client_identity_private_key: PrivateKey,
            server_identity_public_key: PublicKey) -> None:
        nonce_bytes = self._get_nonce_bytes()
        timestamp = self._get_timestamp()
        message_bytes_12 = struct.pack("<I", timestamp) + nonce_bytes

        message_hash = sha256(message_bytes_12)
        client_message_private_key = client_identity_private_key.add(message_hash)
        message_signature_bytes_65 = client_message_private_key.sign_message(message_bytes_12)

        shared_secret_public_key = client_identity_private_key.shared_secret(
            server_identity_public_key, message_bytes_12)
        shared_secret_bytes = int_to_be_bytes(shared_secret_public_key.to_point()[0])
        self._outgoing_cipher = AES.new(shared_secret_bytes, AES.MODE_CTR, nonce=nonce_bytes)
        self._incoming_cipher = AES.new(shared_secret_bytes, AES.MODE_CTR, nonce=nonce_bytes)

        client_identity_public_key = client_identity_private_key.public_key
        return struct.pack("<I33s12s65s", PROTOCOL_VERSION,
            client_identity_public_key.to_bytes(), message_bytes_12, message_signature_bytes_65)

    def _get_nonce_bytes(self) -> bytes:
        return os.urandom(8)


class ServerFramer(BaseFramer):
    _handshaken: bool = False

    def frame(self, data: Dict[str, Any]) -> bytes:
        if not self._handshaken:
            raise ConnectionNotEstablishedError()
        return super().frame(data)

    async def receive_message(self) -> Dict[str, Any]:
        if not self._handshaken:
            return await self._receive_handshake_message()
        return await super().receive_message()

    async def _receive_handshake_message(self) -> Dict[str, Any]:
        logger.debug("_receive_handshake_message")
        payload_bytes = await self.byte_queue.receive(HANDSHAKE_LENGTH)
        protocol_version, client_identity_public_key_bytes, message_bytes, signature_bytes = \
            struct.unpack_from("<I33s12s65s", payload_bytes)
        if protocol_version != PROTOCOL_VERSION:
            raise AuthenticationError(ErrorCodes.INVALID_CLIENT_VERSION,
                "unrecognized protocol version")

        client_identity_public_key = PublicKey.from_bytes(client_identity_public_key_bytes)
        logger.debug("_receive_handshake_message.validate_client_identity")
        account_id = await self.validate_client_identity(client_identity_public_key)
        if account_id is None:
            logger.debug("_receive_handshake_message.exit")
            # TODO(rt12) blacklist ip, have extending period of blacklisting?
            raise AuthenticationError(ErrorCodes.INVALID_CLIENT_IDENTITY,
                "unrecognized client identity key")

        logger.debug("_receive_handshake_message %d", 1)
        timestamp, nonce_bytes = struct.unpack_from("<I8s", message_bytes)
        logger.debug("ts %d %d %d",
            self._get_timestamp(), timestamp, self._get_timestamp() - timestamp)
        if abs(self._get_timestamp() - timestamp) > HANDSHAKE_TIMESTAMP_VARIANCE:
            raise AuthenticationError(ErrorCodes.INVALID_CLIENT_TIMESTAMP,
                "timestamp out of range")

        logger.debug("_receive_handshake_message %d", 2)
        message_hash = sha256(message_bytes)
        client_message_public_key = client_identity_public_key.add(message_hash)
        if not client_message_public_key.verify_message(signature_bytes, message_bytes):
            raise AuthenticationError(ErrorCodes.INVALID_CLIENT_SIGNATURE,
                "invalid client signature")

        shared_secret_bytes = await self.get_shared_secret(account_id, client_identity_public_key,
            message_bytes)
        self._outgoing_cipher = AES.new(shared_secret_bytes, AES.MODE_CTR, nonce=nonce_bytes)
        self._incoming_cipher = AES.new(shared_secret_bytes, AES.MODE_CTR, nonce=nonce_bytes)
        self._handshaken = True

        return {
            "account_id": account_id,
            "identity_key": client_identity_public_key,
            "message_key": client_message_public_key,
        }

    # External API
    async def validate_client_identity(self,
            client_identity_public_key: PublicKey) -> Optional[int]:
        raise NotImplementedError

    async def get_shared_secret(self, account_id: int, client_identity_public_key: PublicKey,
            message_bytes: bytes) -> bytes:
        # shared_secret_public_key = server_id_private_key.shared_secret(client_identity_public_key,
        #     message_bytes)
        # shared_secret_bytes = int_to_be_bytes(shared_secret_public_key.to_point()[0])
        raise NotImplementedError


class Notification(aiorpcx.Notification):
    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "arguments": self.args,
        }

class Request(aiorpcx.Request):
    def to_dict(self, request_id: int) -> Dict[str, Any]:
        return {
            "request_id": request_id,
            "method": self.method,
            "arguments": self.args,
        }

    def send_result(self, result: Any):
        raise NotImplementedError


class HandshakeNotification:
    def __init__(self, account_id: Optional[int]=None, identity_key: Optional[PublicKey]=None,
            message_key: Optional[PublicKey]=None) -> None:
        assert account_id is not None
        self._account_id = account_id
        assert identity_key is not None
        self._identity_public_key = identity_key
        assert message_key is not None
        self._message_public_key = message_key


RequestTypes = Union[Notification, Request, HandshakeNotification]



class Connection:
    def __init__(self) -> None:
        self._requests: Dict[int, Tuple[Request, asyncio.Future]] = {}
        self._create_future = asyncio.get_event_loop().create_future
        self._next_request_id = 1

    def send_batch(self, batch: Iterable[Any]) -> Tuple[Any, Any]: # message, event
        raise NotImplementedError

    def receive_message(self, data: Dict[str, Any]) -> Optional[Iterable[RequestTypes]]:
        if "account_id" in data:
            return [ HandshakeNotification(data["account_id"], data["identity_key"],
                data["message_key"]) ]

        method = data.get("method")
        request_id = data.get("request_id")
        if method is None and request_id is not None:
            self._dispatch_response(request_id, data.get("result"))
            return []

        arguments = data.get("arguments")
        if request_id is None:
            return [ Notification(method, arguments) ]
        request = Request(method, arguments)
        request.send_result = partial(self._create_response_message, request_id)
        return [ request ]

    def cancel_pending_requests(self) -> None:
        '''Cancel all pending requests.'''
        for _request, future in self._requests.values():
            if not future.done():
                future.cancel()
        self._requests.clear()

    def _future(self, request, request_id: int) -> asyncio.Future:
        future = self._create_future()
        self._requests[request_id] = (request, future)
        return future

    def _dispatch_response(self, request_id: int, result: Any) -> None:
        _request, future = self._requests.pop(request_id)
        if not future.done():
            if isinstance(result, Exception):
                future.set_exception(result)
            else:
                future.set_result(result)
        return None

    def _create_request_message(self, request: Request) -> Tuple[Dict[str, Any], asyncio.Future]:
        request_id = self._next_request_id
        self._next_request_id += 1
        return request.to_dict(request_id), self._future(request, request_id)

    def _create_notification_message(self, notification: Notification) -> Dict[str, Any]:
        return notification.to_dict()

    def _create_response_message(self, request_id: int, result: Any) -> None:
        return {
            "request_id": request_id,
            "result": result,
        }


class ServerConnection(Connection):
    _handshaken: bool = False

    def receive_message(self, data: Dict[str, Any]) -> Optional[RequestTypes]:
        if not self._handshaken:
            message = HandshakeNotification(**data)
            self._handshaken = True
            return message
        return super().receive_message(data)


class BaseSession(aiorpcx.RPCSession):
    # External API
    def default_connection(self):
        '''Return a default connection if the user provides none.'''
        return Connection()

    def default_framer(self) -> ClientFramer:
        return ClientFramer()

    async def handle_request(self, request: RequestTypes) -> Any:
        raise NotImplementedError

    async def send_request(self, method, args=()) -> Any:
        '''Send an RPC request over the network.'''
        message, future = self.connection._create_request_message(Request(method, args))
        return await self._send_concurrent(message, future, 1)

    async def send_notification(self, method, args=()) -> None:
        '''Send an RPC notification over the network.'''
        message = self.connection._create_notification_message(Notification(method, args))
        await self._send_message(message)

    def send_batch(self, raise_errors=False):
        raise NotImplementedError


class ClientSession(BaseSession):
    def default_framer(self) -> ClientFramer:
        return ClientFramer()

    async def server_handshake(self, client_private_key: PrivateKey,
            server_public_key: PublicKey) -> None:
        handshake_bytes = self.transport._framer.frame_handshake(client_private_key,
            server_public_key)
        await self._send_message(handshake_bytes)


class ServerSession(BaseSession):
    def default_framer(self) -> ServerFramer:
        framer = ServerFramer()
        framer.validate_client_identity = self.validate_client_identity
        framer.get_shared_secret = self.get_shared_secret
        return framer

    # async def _process_messages(self, recv_message):
    #     try:
    #         return await super()._process_messages(recv_message)
    #     except Exception as e:
    #         traceback.print_exc()
    #         raise e

    async def validate_client_identity(self, public_key: PublicKey) -> Optional[int]:
        # Returns `None` to indicate the identity was not validated.
        # Override and resolve the public key.
        raise NotImplementedError

    # The application needs to override this and employ it's own private key, in order to
    # derive the shared secret. The application can manage the security and privacy of the key
    # as the core code does not need to know it.
    async def get_shared_secret(self, account_id: int, client_identity_public_key: PublicKey,
            message_bytes: bytes) -> bytes:
        # shared_secret_public_key = server_id_private_key.shared_secret(client_identity_public_key,
        #     message_bytes)
        # shared_secret_bytes = int_to_be_bytes(shared_secret_public_key.to_point()[0])
        raise NotImplementedError

