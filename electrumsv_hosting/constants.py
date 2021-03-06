from enum import IntEnum, IntFlag
import struct


NO_MESSAGE_TYPE = 0
ERROR_MESSAGE_TYPE = 1
HANDSHAKE_MESSAGE_TYPE = 2


class PacketType(IntFlag):
    REQUEST = 1 << 0
    RESPONSE = 1 << 1
    NOTIFICATION = 1 << 2

PACKET_TYPE_MASK = PacketType.REQUEST | PacketType.RESPONSE | PacketType.NOTIFICATION


PACKET_TYPE_CHAR = "B"          # 1 unsigned byte.
PACKET_ID_CHAR = "H"            # 1 unsigned short.
PACKET_FMT = "<"+ PACKET_TYPE_CHAR + PACKET_ID_CHAR

PACKET_HEADER_SIZE = struct.calcsize(PACKET_FMT)


MESSAGE_TYPE_CHAR = "B"         # 1 unsigned byte.
MESSAGE_FMT = "<"+ MESSAGE_TYPE_CHAR

MESSAGE_TYPE_SIZE = struct.calcsize(MESSAGE_FMT)

CODE_ERROR = 0

class MessageType(IntEnum):
    HANDSHAKE_REQUEST = HANDSHAKE_MESSAGE_TYPE
    REGISTER_IDENTITY_REQUEST = 99
    REGISTER_IDENTITY_RESPONSE = 100
    SUBSCRIPTION_REQUEST = 101
    SUBSCRIPTION_RESPONSE = 102
    GET_MESSAGE_REQUEST = 103
    GET_MESSAGE_RESPONSE = 104
    SEND_MESSAGE_REQUEST = 105
    SEND_MESSAGE_RESPONSE = 106
