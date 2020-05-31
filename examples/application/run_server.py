import asyncio
import logging
import os
import struct
import sys
import time
from typing import Any, Optional, Dict
from functools import partial

import aiorpcx
from bitcoinx import int_to_be_bytes, PublicKey, PrivateKey
from electrumsv_hosting.core import core
from electrumsv_hosting.messagebox import MessageType

from server.constants import ALICE_TEST_IDENTITY_PUBLIC_KEY, SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY,\
    DATABASE_NAME_VARNAME, BITCOIN_NETWORK_VARNAME, DATABASE_USER_VARNAME, DATABASE_HOST_VARNAME, \
    DATABASE_PORT_VARNAME, DATABASE_PASSWORD_VARNAME, LOGGING_LEVEL_VARNAME
from server import database
from server.session import IncomingClientSession


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("example-mailbox_server")


DEFAULT_ENV_VARS = [
    (DATABASE_NAME_VARNAME, 'mailboxdb', DATABASE_NAME_VARNAME),
    (BITCOIN_NETWORK_VARNAME, "testnet", BITCOIN_NETWORK_VARNAME),
    (DATABASE_USER_VARNAME, 'mailboxadmin', DATABASE_USER_VARNAME),
    (DATABASE_HOST_VARNAME, '127.0.0.1', DATABASE_HOST_VARNAME),
    (DATABASE_PORT_VARNAME, 5432, DATABASE_PORT_VARNAME),
    (DATABASE_PASSWORD_VARNAME, 'mailboxpassword', DATABASE_PASSWORD_VARNAME)
]


def setup_logging() -> None:
    log_path = os.path.join(os.getcwd(), "logs")
    os.makedirs(log_path, exist_ok=True)
    logfile_path = os.path.join(log_path, time.strftime("%Y%m%d-%H%M%S") + ".log")
    file_handler = logging.FileHandler(logfile_path)
    formatter = logging.Formatter('%(asctime)s:' + logging.BASIC_FORMAT)
    file_handler.setFormatter(formatter)
    logging.root.addHandler(file_handler)


def set_logging_level() -> None:
    logging_level = logging.DEBUG
    if LOGGING_LEVEL_VARNAME in os.environ:
        logging_level_name = os.environ[LOGGING_LEVEL_VARNAME].lower()
        logging_levels = {
            "info": logging.INFO,
            "warning": logging.WARNING,
            "critical": logging.CRITICAL,
            "debug": logging.DEBUG,
            "error": logging.ERROR,
        }
        if logging_level_name not in logging_levels:
            print(f"Environment variable '{LOGGING_LEVEL_VARNAME}' invalid. "
                  f"Must be one of {logging_levels.keys()}")
            sys.exit(1)
        logging_level = logging_levels[logging_level_name]
    logging.root.setLevel(logging_level)


def get_configuration() -> Dict:
    config = {}
    setup_logging()
    for varname, vardefault, configname in DEFAULT_ENV_VARS:
        varvalue = vardefault
        if varname in os.environ:
            varvalue = type(vardefault)(os.environ[varname])
        config[configname] = varvalue

    set_logging_level()
    return config


def setup():
    config = {}
    config.update(get_configuration())
    database.load(config)
    return config


def loop_exception_handler(loop, context) -> None:
    logger.debug('Exception handler called')
    logger.debug(context)


class ServerApplication:
    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop
        self.dbapi = database.DatabaseAPI()

        self.server_private_key = SERVER_PRIVATE_KEY
        self.server_public_key = SERVER_PUBLIC_KEY

    def create_session(self, *args, **kwargs) -> IncomingClientSession:
        return IncomingClientSession(self, *args, **kwargs)

    def sign_message(self, receiver_pubkey: PublicKey, timestamp: int, nonce_bytes: bytes,
            payload_hash: bytes) -> bytes:
        message_bytes = (receiver_pubkey.to_bytes() + struct.pack("<I", timestamp) +
            nonce_bytes + payload_hash)
        logger.debug("for signing: %s", message_bytes)
        return self.server_private_key.sign_message(message_bytes)


def main():
    setup()

    async def wakeup():
        while True:
            await asyncio.sleep(0.2)

    loop = asyncio.get_event_loop()
    loop.set_exception_handler(loop_exception_handler)

    app = ServerApplication(loop)
    _restricted_server = loop.run_until_complete(
        aiorpcx.serve_rs(app.create_session, 'localhost', 8888))

    loop.create_task(wakeup())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        database.db.close()


if __name__ == "__main__":
    main()
