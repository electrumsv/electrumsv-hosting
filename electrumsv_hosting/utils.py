import base64
import binascii
import logging
import os
import time

import bitcoinx

logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger("utils")


def binary_to_hex(bin) -> str:
    return binascii.hexlify(bin).decode()


def get_nonce() -> bytes:
    return os.urandom(8)


def hash_payload(payload: bytes) -> bytes:
    return bitcoinx.sha256(payload)


def bytes_to_base64(payload: bytes) -> str:
    return base64.b64encode(payload).decode()


def get_timestamp() -> int:
    return int(time.time())


def int_to_hex(num, upper=False):
    hexed = hex(num)[2:]
    if len(hexed) % 2 != 0:
        hexed = '0' + hexed
    return hexed.upper() if upper else hexed


def hex_to_int(hexed):
    return int(hexed, 16)