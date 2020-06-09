import struct
from typing import Optional, Type

from bitcoinx import PrivateKey, PublicKey

from .constants import MESSAGE_FMT, MESSAGE_TYPE_SIZE, MessageType
from .connection import BaseStructure, Message


class EmptyMessage(Message):
    @classmethod
    def from_bytes(klass, buffer: bytes) -> Type['EmptyMessage']:
        return klass()


class MessageHeader(BaseStructure):
    FMT = "33s33s8s32s65s"

    def __init__(self, sender_pubkey: PublicKey, receiver_pubkey: PublicKey, sender_nonce: bytes,
            payload_hash: bytes, sender_signature: Optional[bytes]=None) -> None:
        self.sender_pubkey = sender_pubkey
        self.receiver_pubkey = receiver_pubkey
        self.sender_nonce = sender_nonce
        self.payload_hash = payload_hash
        self.sender_signature = sender_signature

    def sign(self, sender_private_key: PrivateKey) -> None:
        for_signing: str = self.sender_pubkey.to_bytes() + self.receiver_pubkey.to_bytes() \
            + self.sender_nonce + self.payload_hash
        self.sender_signature = sender_private_key.sign_message(for_signing)

    @classmethod
    def from_bytes(klass, data: bytes, offset: int=0) -> 'MessageHeader':
        sender_pubkey_bytes, receiver_pubkey_bytes, sender_nonce, payload_hash, \
            sender_signature = struct.unpack_from(klass.FMT, data, offset)
        sender_pubkey = PublicKey.from_bytes(sender_pubkey_bytes)
        receiver_pubkey = PublicKey.from_bytes(receiver_pubkey_bytes)
        return MessageHeader(sender_pubkey, receiver_pubkey, sender_nonce, payload_hash,
            sender_signature)

    def pack_into(self, buffer: bytearray, offset: int=0) -> None:
        assert self.sender_signature is not None, "message header has not been signed"
        struct.pack_into(self.FMT, buffer, offset,
            self.sender_pubkey.to_bytes(), self.receiver_pubkey.to_bytes(),
            self.sender_nonce, self.payload_hash, self.sender_signature)


class SubscriptionRequest(EmptyMessage):
    message_type = MessageType.SUBSCRIPTION_REQUEST


class SubscriptionResponse(Message):
    message_type = MessageType.SUBSCRIPTION_RESPONSE

    COUNT_FMT = "I"
    FMT = MESSAGE_FMT + COUNT_FMT

    def __init__(self, latest_id: int) -> None:
        self.latest_id = latest_id

    @classmethod
    def from_bytes(self, data: bytes) -> 'SubscriptionResponse':
        _message_type, latest_id = struct.unpack_from(self.FMT, data)
        return SubscriptionResponse(latest_id)

    def pack_into(self, buffer: bytearray, offset: int=0) -> None:
        struct.pack_into(self.FMT, buffer, offset, self.message_type, self.latest_id)


class GetMessageRequest(Message):
    message_type = MessageType.GET_MESSAGE_REQUEST

    ID_FMT = "I"
    FMT = MESSAGE_FMT + ID_FMT

    def __init__(self, message_id: int) -> None:
        self.message_id = message_id

    @classmethod
    def from_bytes(self, data: bytes) -> 'GetMessageRequest':
        _message_type, message_id = struct.unpack_from(self.FMT, data)
        return GetMessageRequest(message_id)

    def pack_into(self, buffer: bytearray, offset: int=0) -> None:
        struct.pack_into(self.FMT, buffer, offset, self.message_type, self.message_id)


class HeaderDataMessage(Message):
    # FMT is the Message version and not representative of the payload data.

    def __init__(self, header: MessageHeader, data: bytes) -> None:
        self.header = header
        self.data = data

    @classmethod
    def from_bytes(klass, buffer: bytes) -> Type['HeaderDataMessage']:
        header = MessageHeader.from_bytes(buffer, MESSAGE_TYPE_SIZE)
        data = buffer[MESSAGE_TYPE_SIZE + len(header):]
        return klass(header, data)

    def pack_into(self, buffer: bytearray, offset: int=0) -> None:
        super().pack_into(buffer, offset)
        offset += MESSAGE_TYPE_SIZE
        self.header.pack_into(buffer, offset)
        offset += len(self.header)
        buffer[offset:] = self.data

    def __len__(self) -> int:
        return MESSAGE_TYPE_SIZE + len(self.header) + len(self.data)


class GetMessageResponse(HeaderDataMessage):
    message_type = MessageType.GET_MESSAGE_RESPONSE


class SendMessageRequest(HeaderDataMessage):
    message_type = MessageType.SEND_MESSAGE_REQUEST


class SendMessageResponse(EmptyMessage):
    message_type = MessageType.SEND_MESSAGE_RESPONSE


class RegisterIdentityRequest(EmptyMessage):
    message_type = MessageType.REGISTER_IDENTITY_REQUEST


class RegisterIdentityResponse(EmptyMessage):
    message_type = MessageType.REGISTER_IDENTITY_RESPONSE


RegisterIdentityRequest.register()
RegisterIdentityResponse.register()
SubscriptionRequest.register()
SubscriptionResponse.register()
GetMessageRequest.register()
GetMessageResponse.register()
SendMessageRequest.register()
SendMessageResponse.register()
