from enum import IntEnum
import struct
from typing import Type

from electrumsv_hosting.connection import HandshakeNotification, Message
from electrumsv_hosting.constants import HANDSHAKE_MESSAGE_TYPE, MESSAGE_TYPE_SIZE


class MessageType(IntEnum):
    HANDSHAKE_REQUEST = HANDSHAKE_MESSAGE_TYPE
    ECHO_REQUEST = 101
    ECHO_RESPONSE = 102
    SUM_REQUEST = 103
    SUM_RESPONSE = 104


class ErrorCode(IntEnum):
    UNKNOWN_MESSAGE_TYPE = 1


class DataMessage(Message):
    # FMT is the Message version and not representative of the payload data.

    def __init__(self, data: bytes) -> None:
        self.data = data

    @classmethod
    def from_bytes(klass, buffer: bytes) -> Type['DataMessage']:
        return klass(buffer[MESSAGE_TYPE_SIZE:])

    def pack_into(self, buffer: bytearray, offset: int=0) -> None:
        super().pack_into(buffer, offset)
        offset += len(self)
        buffer[offset:] = self.data


class EchoMessageRequest(DataMessage):
    message_type = MessageType.ECHO_REQUEST


class EchoMessageResponse(DataMessage):
    message_type = MessageType.ECHO_RESPONSE


class SumMessageRequest(Message):
    message_type = MessageType.SUM_REQUEST

    VALUES_FMT = "II"
    FMT = Message.FMT + VALUES_FMT

    def __init__(self, l_value: int, r_value: int) -> None:
        self.l_value = l_value
        self.r_value = r_value

    @classmethod
    def from_bytes(self, data: bytes) -> 'SumMessageRequest':
        _message_type, l_value, r_value = struct.unpack_from(self.FMT, data)
        return SumMessageRequest(l_value, r_value)

    def pack_into(self, buffer: bytearray, offset: int=0) -> None:
        struct.pack_into(self.FMT, buffer, offset, self.message_type, self.l_value, self.r_value)


class SumMessageResponse(Message):
    message_type = MessageType.SUM_RESPONSE

    VALUE_FMT = "I"
    FMT = Message.FMT + VALUE_FMT

    def __init__(self, value: int) -> None:
        self.value = value

    @classmethod
    def from_bytes(self, data: bytes) -> 'SumMessageResponse':
        _message_type, value = struct.unpack_from(self.FMT, data)
        return SumMessageResponse(value)

    def pack_into(self, buffer: bytearray, offset: int=0) -> None:
        struct.pack_into(self.FMT, buffer, offset, self.message_type, self.value)


EchoMessageRequest.register()
EchoMessageResponse.register()
SumMessageRequest.register()
SumMessageResponse.register()
HandshakeNotification.register()
