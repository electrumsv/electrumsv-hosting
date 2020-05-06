import asyncio
import logging
import os
import sys
import time
from typing import Any, Optional, Dict
from functools import partial

import aiorpcx
from bitcoinx import int_to_be_bytes, PublicKey, PrivateKey
from electrumsv_hosting.core import core

from server.handlers import RestrictedHandlers, PublicHandlers
from server.constants import ALICE_TEST_IDENTITY_PUBLIC_KEY, SERVER_PRIVATE_KEY, \
    DATABASE_NAME_VARNAME, BITCOIN_NETWORK_VARNAME, DATABASE_USER_VARNAME, DATABASE_HOST_VARNAME, \
    DATABASE_PORT_VARNAME, DATABASE_PASSWORD_VARNAME, LOGGING_LEVEL_VARNAME
from server import database


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("example-mailbox_server")

public_handlers = PublicHandlers()
restricted_handlers = RestrictedHandlers(SERVER_PRIVATE_KEY)


class RestrictedServerSession(core.ServerSession):
    """A TCP Server that connects to a bitcoin wallet client via WP42 tunneling"""

    client_identity_pubkey: Optional[PublicKey] = None
    account_id: Optional[int] = None

    def __init__(self, app: 'ServerApplication', *args, **kwargs) -> None:
        self.app = app
        super().__init__(*args, **kwargs)
        logger.debug('connection from %s', self.remote_address())

    def send_batch(self, raise_errors=False):
        raise NotImplementedError

    async def connection_lost(self):
        await super().connection_lost()
        logger.debug(f'{self.remote_address()} disconnected')

    def get_handlers(self) -> Any:
        if self.account_id is None:
            return public_handlers
        return restricted_handlers

    async def handle_request(self, request: core.RequestTypes) -> Any:
        if isinstance(request, core.HandshakeNotification):
            self.client_identity_pubkey = request.identity_public_key
            self.account_id = self.app.dbapi.get_account_id_for_identity_pubkey(
                self.client_identity_pubkey)
            return None

        # logger.debug("handle_request:enter '%s'", request.method)
        handler_func = self.get_handlers().get(request.method)
        if handler_func is None:
            logger.debug("bad handler for '%s'", request.method)
        handler = partial(handler_func, self)
        coro = aiorpcx.handler_invocation(handler, request)()
        ret = await coro
        # logger.debug("handle_request:exit")
        return ret

    async def get_shared_secret(self, client_identity_public_key: PublicKey,
            message_bytes: bytes) -> bytes:
        shared_secret_public_key = SERVER_PRIVATE_KEY.shared_secret(client_identity_public_key,
            message_bytes)
        return int_to_be_bytes(shared_secret_public_key.to_point()[0])

    def set_account_id(self, account_id: int) -> None:
        self.account_id = account_id


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

    def create_session(self, *args, **kwargs) -> RestrictedServerSession:
        return RestrictedServerSession(self, *args, **kwargs)

def main():
    setup()

    async def wakeup():
        while True:
            await asyncio.sleep(0.2)

    loop = asyncio.get_event_loop()
    loop.set_exception_handler(loop_exception_handler)

    # handlers = RestrictedHandlers(SERVER_PRIVATE_KEY)
    # session_factory = partial(RestrictedServerSession, SERVER_PRIVATE_KEY, handlers)
    # restricted_server = loop.run_until_complete(
    #     aiorpcx.serve_rs(session_factory, 'localhost', 8888))

    app = ServerApplication(loop)
    restricted_server = loop.run_until_complete(
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
