import logging
from typing import Any, Optional, Dict

from bitcoinx import int_to_be_bytes, PublicKey

from electrumsv_hosting.connection import Message, ServerSession
from electrumsv_hosting.messagebox import MessageType

from server.handlers import BaseAPI, PublicAPI, RestrictedAPI


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("example-mailbox_server")

public_api = PublicAPI()
restricted_api = RestrictedAPI()


class IncomingClientSession(ServerSession):
    """A TCP Server that connects to a bitcoin wallet client via WP42 tunneling"""

    client_identity_pubkey: Optional[PublicKey] = None
    client_identity_id: Optional[int] = None

    def __init__(self, app: 'ServerApplication', *args, **kwargs) -> None:
        self.app = app
        super().__init__(*args, **kwargs)
        logger.debug('connection from %s', self.remote_address())

    def send_batch(self, raise_errors=False):
        raise NotImplementedError

    async def connection_lost(self) -> None:
        await super().connection_lost()
        logger.debug(f'{self.remote_address()} disconnected')

    async def handle_request(self, request_message: Message) -> Any:
        logger.debug("handle_request:enter '%s'", request_message.message_type)
        api: BaseAPI = public_api if self.client_identity_id is None else restricted_api
        response_message = await api.dispatch_message(self, request_message)
        logger.debug("handle_request:exit")
        return response_message

    async def get_shared_secret(self, client_identity_public_key: PublicKey,
            message_bytes: bytes) -> bytes:
        shared_secret_public_key = self.app.server_private_key.shared_secret(
            client_identity_public_key, message_bytes)
        return int_to_be_bytes(shared_secret_public_key.to_point()[0])

    async def on_handshake(self, identity_public_key: PublicKey) -> None:
        self.client_identity_pubkey = identity_public_key
        self.client_identity_id = self.app.dbapi.get_id_for_identity(
            identity_public_key)

    async def on_register_identity(self, identity_id: int) -> None:
        self.client_identity_id = identity_id

