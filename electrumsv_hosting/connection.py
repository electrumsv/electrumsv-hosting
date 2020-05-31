# TODO: Set the encryption things on the framer when handshaked.
# TODO: Set the framer handshaked flag.
# TODO: Decide how to manage the private key, wrt shared secrets and signing.

import asyncio
import base64
import enum
import json
import logging
import os
from functools import partial
import struct
import time
import traceback
from typing import Any, Dict, Iterable, Optional, Tuple, Type, Union

import aiorpcx
import aiorpcx.framing
from bitcoinx import int_to_be_bytes, PrivateKey, PublicKey, sha256
from Cryptodome.Cipher import AES, _mode_ctr

from .constants import (ERROR_MESSAGE_TYPE, HANDSHAKE_MESSAGE_TYPE, MESSAGE_FMT, NO_MESSAGE_TYPE,
    PACKET_HEADER_SIZE, PACKET_FMT, PacketType)
from .exceptions import AuthenticationError, ConnectionNotEstablishedError
from .utils import get_nonce, get_timestamp


logger = logging.getLogger("esvhosting-core")

PROTOCOL_VERSION = 1
HANDSHAKE_TIMESTAMP_VARIANCE = 5

class ErrorCodes(enum.IntEnum):
    INVALID_CLIENT_SIGNATURE = 20001
    INVALID_CLIENT_TIMESTAMP = 20002
    INVALID_CLIENT_VERSION = 20003


class Header:
    def __init__(self, sender_pubkey: PublicKey, receiver_pubkey: Optional[PublicKey],
            sender_nonce: bytes, payload_hash, sender_signature: bytes):
        self.sender_pubkey = sender_pubkey
        self.receiver_pubkey = receiver_pubkey
        self.sender_nonce = sender_nonce
        self.payload_hash = payload_hash
        self.sender_signature = sender_signature

        # dic = {'sender_pubkey': self.sender_pubkey.to_hex(),
        #      'sender_nonce': binary_to_hex(self.sender_nonce),
        #      'payload_hash': binary_to_hex(self.payload_hash),
        #      'sender_signature': base64.b64encode(self.sender_signature).decode()}
        # if self.receiver_pubkey is not None:
        #     dic.update({'receiver_pubkey': self.receiver_pubkey.to_hex()})

        # return cls(sender_pubkey=PublicKey.from_hex(dic['sender_pubkey']),
        #     receiver_pubkey=PublicKey.from_hex(dic.get('receiver_pubkey')) if dic.get(
        #         'receiver_pubkey') is not None else None,
        #     sender_nonce=bytes.fromhex(dic['sender_nonce']),
        #     payload_hash=bytes.fromhex(dic['payload_hash']),
        #     sender_signature=base64.b64decode(dic['sender_signature']))


class BaseStructure:
    FMT = ""

    def to_bytes(self) -> bytearray:
        buffer = bytearray(len(self))
        self.pack_into(buffer)
        return buffer

    def pack_into(self, buffer: bytearray, offset: int=0) -> None:
        raise NotImplementedError

    def __len__(self) -> int:
        return struct.calcsize(self.FMT)


class Message(BaseStructure):
    message_type: int = NO_MESSAGE_TYPE
    message_handlers: Dict[int, Type['Message']] = {}

    # The subclass should ensure there is a valid value for this attribute.
    FMT = MESSAGE_FMT

    def __init__(self) -> None:
        pass

    @classmethod
    def register(klass: Type['Message']) -> None:
        logger.debug("registered message type %s", klass.message_type)
        klass.message_handlers[klass.message_type] = klass

    @classmethod
    def from_bytes(self, data: bytes) -> 'Message':
        message_type, = struct.unpack_from(MESSAGE_FMT, data)
        message_class = self.message_handlers.get(message_type)
        if message_class is None:
            logger.debug("unregistered message type %s", message_type)
            raise NotImplementedError
        # if message_class.FMT == MESSAGE_FMT:
        #     return message_class()
        return message_class.from_bytes(data)

    def to_bytes(self) -> bytearray:
        buffer = bytearray(len(self))
        self.pack_into(buffer)
        return buffer

    def pack_into(self, buffer: bytearray, offset: int=0) -> None:
        struct.pack_into(self.FMT, buffer, offset, self.message_type)

    def __len__(self) -> int:
        return struct.calcsize(self.FMT)


class HandshakeNotification(Message):
    message_type = HANDSHAKE_MESSAGE_TYPE

    VERSION_FMT = "I"
    KEY_FMT = "33s"
    TIMESTAMP_FMT = "I"
    NONCE_FMT = "8s"
    SIGNATURE_FMT = "65s"
    FMT = MESSAGE_FMT + VERSION_FMT + KEY_FMT + TIMESTAMP_FMT + NONCE_FMT + SIGNATURE_FMT

    def __init__(self, version: int, public_key: PublicKey, timestamp: int=0,
            nonce_bytes: Optional[bytes]=None,
            signature_bytes: Optional[bytes]=None) -> None:
        self.version = version
        self.remote_public_key = public_key
        self.timestamp = timestamp if timestamp != 0 else get_timestamp()
        self.nonce_bytes = nonce_bytes if nonce_bytes is not None else get_nonce()
        self.signature_bytes = signature_bytes

    def get_message_bytes(self) -> bytes:
        return struct.pack("<I8s", self.timestamp, self.nonce_bytes)

    def sign(self, private_key: PrivateKey) -> None:
        message_bytes = self.get_message_bytes()
        message_hash = sha256(message_bytes)
        self.signature_bytes = private_key.add(message_hash).sign_message(message_bytes)

    def validate(self) -> None:
        logger.debug("HandshakeNotification.check")
        if self.version != PROTOCOL_VERSION:
            raise AuthenticationError(ErrorCodes.INVALID_CLIENT_VERSION,
                "unrecognized protocol version")

        if abs(get_timestamp() - self.timestamp) > HANDSHAKE_TIMESTAMP_VARIANCE:
            raise AuthenticationError(ErrorCodes.INVALID_CLIENT_TIMESTAMP,
                "timestamp out of range")

        message_bytes = self.get_message_bytes()
        message_hash = sha256(message_bytes)
        message_public_key = self.remote_public_key.add(message_hash)
        if not message_public_key.verify_message(self.signature_bytes, message_bytes):
            raise AuthenticationError(ErrorCodes.INVALID_CLIENT_SIGNATURE,
                "invalid client signature")

    @classmethod
    def from_bytes(self, data: bytes) -> 'HandshakeNotification':
        _message_type, protocol_version, identity_key_data, timestamp, nonce_bytes, \
            signature_bytes = struct.unpack_from(self.FMT, data)
        remote_public_key = PublicKey.from_bytes(identity_key_data)
        return HandshakeNotification(protocol_version, remote_public_key, timestamp, nonce_bytes,
            signature_bytes)

    def pack_into(self, buffer: bytearray, offset: int=0) -> None:
        struct.pack_into(self.FMT, buffer, offset, self.message_type, self.version,
            self.remote_public_key.to_bytes(), self.timestamp, self.nonce_bytes,
            self.signature_bytes)

    def __repr__(self) -> str:
        return "<HandshakeNotification protocol=%d id_key=%s ts=%d nonce=%s signature=%s>" % (
            self.version, self.remote_public_key.to_hex(), self.timestamp, self.nonce_bytes.hex(),
            self.signature_bytes.hex())


class ErrorMessage(Message):
    message_type = ERROR_MESSAGE_TYPE

    CODE_FMT = "I"
    FMT = MESSAGE_FMT + CODE_FMT
    FMT_SIZE = struct.calcsize(FMT)

    def __init__(self, code: int, data: bytes) -> None:
        self.code = code
        self.data = data

    @classmethod
    def from_bytes(klass, buffer: bytes) -> 'ErrorMessage':
        _message_type, code = struct.unpack_from(klass.FMT, buffer)
        data = buffer[klass.FMT_SIZE:]
        return klass(code, data)

    def pack_into(self, buffer: bytearray, offset: int=0) -> None:
        struct.pack_into(self.FMT, buffer, offset, self.message_type, self.code)
        offset += self.FMT_SIZE
        buffer[offset:] = self.data

    def __len__(self) -> int:
        return self.FMT_SIZE + len(self.data)

    def __repr__(self) -> str:
        return "<ErrorMessage code=%d message='%s'>" % (self.code, self.data)


class Packet:
    def __init__(self, type: PacketType, message: Message, id: int=0) -> None:
        self.packet_type = type
        self.packet_id = id
        self.message = message

    @classmethod
    def from_bytes(klass, data: bytes) -> 'Packet':
        packet_type, packet_id = struct.unpack_from(PACKET_FMT, data)
        message = Message.from_bytes(data[PACKET_HEADER_SIZE:])
        return Packet(packet_type, message, packet_id)

    def to_bytes(self) -> bytearray:
        buffer = bytearray(len(self))
        self.pack_into(buffer)
        return buffer

    def pack_into(self, buffer: bytearray, offset: int=0) -> None:
        struct.pack_into(PACKET_FMT, buffer, offset, self.packet_type, self.packet_id)
        self.message.pack_into(buffer, offset + PACKET_HEADER_SIZE)

    def __len__(self) -> int:
        return PACKET_HEADER_SIZE + len(self.message)


class BaseFramer:
    _incoming_cipher: Optional[_mode_ctr.CtrMode] = None
    _outgoing_cipher: Optional[_mode_ctr.CtrMode] = None

    def __init__(self) -> None:
        self.byte_queue = aiorpcx.framing.ByteQueue()
        self.received_bytes = self.byte_queue.put_nowait
        self.fail = self.byte_queue.fail

    def setup_encryption(self, shared_secret_bytes: bytes, nonce_bytes: bytes) -> None:
        self._outgoing_cipher = AES.new(shared_secret_bytes, AES.MODE_CTR, nonce=nonce_bytes)
        self._incoming_cipher = AES.new(shared_secret_bytes, AES.MODE_CTR, nonce=nonce_bytes)

    def frame(self, packet: Packet) -> bytes:
        assert isinstance(packet, Packet), f'{packet}'
        packet_bytes = packet.to_bytes()
        if packet.message.message_type != HANDSHAKE_MESSAGE_TYPE:
            packet_bytes = self._outgoing_cipher.encrypt(packet_bytes)
        return b''.join((
            struct.pack("<I", len(packet_bytes)),
            packet_bytes,
        ))

    def process_payload(self, payload_bytes: bytes) -> bytes:
        return self._incoming_cipher.decrypt(payload_bytes)

    async def receive_message(self) -> Packet:
        payload_size_bytes = await self.byte_queue.receive(4)
        payload_size = struct.unpack("<I", payload_size_bytes)[0]

        payload_bytes = await self.byte_queue.receive(payload_size)
        payload_bytes = self.process_payload(payload_bytes)
        return Packet.from_bytes(payload_bytes)


class ClientFramer(BaseFramer):
    pass


class ServerFramer(BaseFramer):
    _handshaken: bool = False

    def frame(self, data: Dict[str, Any]) -> bytes:
        if not self._handshaken:
            raise ConnectionNotEstablishedError()
        return super().frame(data)

    def process_payload(self, payload_bytes: bytes) -> bytes:
        if not self._handshaken:
            return payload_bytes
        return super().process_payload(payload_bytes)

    def setup_encryption(self, shared_secret_bytes: bytes, nonce_bytes: bytes) -> None:
        self._handshaken = True
        super().setup_encryption(shared_secret_bytes, nonce_bytes)


class Connection:
    def __init__(self) -> None:
        self._request_futures: Dict[int, asyncio.Future] = {}
        self._create_future = asyncio.get_event_loop().create_future
        self._next_request_id = 1

    def send_batch(self, batch: Iterable[Any]) -> Tuple[Any, Any]: # message, event
        raise NotImplementedError

    # Called by session._process_messages with a deframed packet.
    # Should raise ProtocolError if there is a problem. Protocol.error_message is framed and
    # returned, should it be raised.
    def receive_message(self, packet: Packet) -> Optional[Iterable[Packet]]:
        if packet.packet_type == PacketType.RESPONSE:
            self._dispatch_response(packet)
            return []
        return [ packet ]

    def cancel_pending_requests(self) -> None:
        '''Cancel all pending requests.'''
        for future in self._request_futures.values():
            if not future.done():
                future.cancel()
        self._request_futures.clear()

    def _future(self, request_id: int) -> asyncio.Future:
        future = self._create_future()
        self._request_futures[request_id] = future
        return future

    def _dispatch_response(self, packet: Packet) -> None:
        future = self._request_futures.pop(packet.packet_id)
        if not future.done():
            # We do not currently support returning errors.
            # if isinstance(packet, Exception):
            #     future.set_exception(packet.message)
            # else:
            future.set_result(packet.message)
        return None

    def get_next_request_id(self) -> int:
        request_id = self._next_request_id
        self._next_request_id += 1
        return request_id


class ServerConnection(Connection):
    _handshaken: bool = False

    def receive_message(self, packet: Packet) -> Packet:
        if not self._handshaken:
            assert packet.message.message_type == HANDSHAKE_MESSAGE_TYPE

            self._handshaken = True
            return []

        assert packet.message.message_type != HANDSHAKE_MESSAGE_TYPE
        return super().receive_message(packet)


class BaseSession(aiorpcx.RPCSession):
    # External API
    def default_connection(self):
        '''Return a default connection if the user provides none.'''
        return Connection()

    async def handle_request(self, request_packet: Packet) -> Any:
        # TODO: We cannot raise any errors and expect them to be returned to the caller, in the
        # event it is a request, rather than a notification, because that is done via the
        # Request class, which is method/arguments JSON-RPC oriented.  So we need to catch
        # the exceptions here and send the response ourselves, and just I guess reraise
        # them as RPC errors.
        try:
            message = await self.handle_message(request_packet.message)
        except aiorpcx.RPCError as e:
            logger.exception("response RPCError")
            message = ErrorMessage(e.code, e.message)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("unexpected exception")
            raise

        if request_packet.packet_type == PacketType.REQUEST:
            response_packet = Packet(PacketType.RESPONSE, message, request_packet.packet_id)
            await self._send_message(response_packet)
        elif request_packet.packet_type != PacketType.NOTIFICATION:
            raise NotImplementedError
        return None

    async def handle_message(self, message: Message) -> Any:
        pass

    async def send_request(self, message: Message) -> Message:
        '''Send an RPC request over the network.'''
        request_id = self.connection.get_next_request_id()
        packet = Packet(PacketType.REQUEST, message, request_id)
        return await self._send_concurrent(packet, self.connection._future(request_id),
            1)

    async def send_notification(self, message: Message) -> None:
        '''Send an RPC notification over the network.'''
        packet = Packet(PacketType.NOTIFICATION, message)
        await self._send_message(packet)

    def send_batch(self, raise_errors=False):
        raise NotImplementedError

    # The application needs to override this and employ it's own private key, in order to
    # derive the shared secret. The application can manage the security and privacy of the key
    # as the core code does not need to know it.
    async def get_shared_secret(self, remote_public_key: PublicKey, message_bytes: bytes) -> bytes:
        # shared_secret_public_key = server_id_private_key.shared_secret(remote_public_key,
        #     message_bytes)
        # shared_secret_bytes = int_to_be_bytes(shared_secret_public_key.to_point()[0])
        raise NotImplementedError


class ClientSession(BaseSession):
    def default_framer(self) -> ClientFramer:
        return ClientFramer()

    async def server_handshake(self, client_private_key: PrivateKey,
            server_public_key: PublicKey) -> None:
        logger.debug("client handshake: sending")
        message = HandshakeNotification(PROTOCOL_VERSION, client_private_key.public_key)
        message.sign(client_private_key)

        secret_message_bytes = message.get_message_bytes()
        shared_secret = await self.get_shared_secret(server_public_key, secret_message_bytes)
        self.transport._framer.setup_encryption(shared_secret, message.nonce_bytes)

        # This has an exception for the handshake message, to prevent it encrypting itself.
        await self.send_notification(message)
        logger.debug("client handshake: sent")


class ServerSession(BaseSession):
    def default_framer(self) -> ServerFramer:
        return ServerFramer()

    async def _process_messages(self, recv_message) -> None:
        try:
            await super()._process_messages(recv_message)
        except aiorpcx.rawsocket.ConnectionLostError:
            raise
        except Exception as e:
            traceback.print_exc()
            raise e

    async def handle_request(self, packet: Packet) -> Any:
        if packet.message.message_type == HANDSHAKE_MESSAGE_TYPE:
            logger.debug("server handshake: processing")
            message: HandshakeNotification = packet.message
            message.validate()

            secret_message_bytes = message.get_message_bytes()
            shared_secret = await self.get_shared_secret(message.remote_public_key,
                secret_message_bytes)
            self.transport._framer.setup_encryption(shared_secret, message.nonce_bytes)
            logger.debug("server handshake: processed")
            return None

        await super().handle_request(packet)
        return None

