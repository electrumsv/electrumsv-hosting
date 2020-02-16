from typing import Optional

import pytest

from bitcoinx import int_to_be_bytes, PrivateKey, PublicKey

from electrumsv_hosting import core


client_private_key_bytes = bytes.fromhex(
    '249fcf3bf728e8004d58c7f63acf9f1f75b80884843a9682b30dbe3b83f6cbda')
client_private_key = PrivateKey(client_private_key_bytes)
client_message_key_hex = '03ad925e7a3304acca114de77ec8bcb480d3d504da8a4cb055526d81f82c71d978'
client_nonce_bytes = bytes.fromhex('b1667bcd69ef578d')
client_timestamp = 1581395767

server_private_key_bytes = bytes.fromhex(
    '6feba37e2c41c1caf6a2e6ee45e432da43d5eb34b61951df2833fe47bfbf65af')
server_private_key = PrivateKey(server_private_key_bytes)

expected_shared_secret_bytes = bytes.fromhex(
    "b460676d590eb7912c683474c6d16f94b4f84576d18d4564d055535a6c73c23b")


async def get_shared_secret_standard(account_id: int, client_identity_public_key: PublicKey,
        message_bytes: bytes) -> bytes:
    shared_secret_public_key = server_private_key.shared_secret(client_identity_public_key,
        message_bytes)
    return int_to_be_bytes(shared_secret_public_key.to_point()[0])


class PredictableClientFramer(core.ClientFramer):
    def _get_nonce_bytes(self) -> bytes:
        global client_nonce_bytes
        return client_nonce_bytes

    def _get_timestamp(self) -> int:
        global client_timestamp
        return client_timestamp


class PredictableServerFramer(core.ServerFramer):
    _timestamp = client_timestamp

    def set_timestamp(self, timestamp: int) -> None:
        self._timestamp = timestamp

    def _get_timestamp(self) -> int:
        return self._timestamp


def test_server_frame_no_handshake() -> None:
    server_framer = core.ServerFramer()
    with pytest.raises(core.ConnectionNotEstablishedError):
        server_framer.frame({})


@pytest.mark.asyncio
async def test_handshake_framing() -> None:
    client_framer = PredictableClientFramer()
    client_handshake_message_bytes = client_framer.frame_handshake(client_private_key,
        server_private_key.public_key)
    assert len(client_handshake_message_bytes) == core.HANDSHAKE_LENGTH

    async def validate_client_identity(client_identity_public_key: PublicKey) -> Optional[int]:
        return 1

    shared_secret_bytes: Optional[bytes] = None
    async def get_shared_secret(account_id: int, client_identity_public_key: PublicKey,
            message_bytes: bytes) -> bytes:
        nonlocal shared_secret_bytes
        shared_secret_bytes = await get_shared_secret_standard(account_id,
            client_identity_public_key, message_bytes)
        return shared_secret_bytes

    server_framer = PredictableServerFramer()
    server_framer.validate_client_identity = validate_client_identity
    server_framer.get_shared_secret = get_shared_secret

    assert not server_framer._handshaken
    server_framer.received_bytes(client_handshake_message_bytes)
    result = await server_framer._receive_handshake_message()
    assert server_framer._handshaken
    assert 1 == result["account_id"]
    assert client_private_key.public_key == result["identity_key"]
    assert client_message_key_hex == result["message_key"].to_hex()
    assert expected_shared_secret_bytes == shared_secret_bytes


@pytest.mark.asyncio
async def test_handshake_framing_identity_fail() -> None:
    client_framer = core.ClientFramer()
    client_handshake_message_bytes = client_framer.frame_handshake(client_private_key,
        server_private_key.public_key)

    async def validate_client_identity(client_identity_public_key: PublicKey) -> Optional[int]:
        return None

    server_framer = core.ServerFramer()
    server_framer.validate_client_identity = validate_client_identity

    server_framer.received_bytes(client_handshake_message_bytes)
    with pytest.raises(core.AuthenticationError) as e:
        await server_framer._receive_handshake_message()

    assert core.ErrorCodes.INVALID_CLIENT_IDENTITY == e.value.args[0]


@pytest.mark.asyncio
async def test_handshake_framing_timing_fail() -> None:
    client_framer = PredictableClientFramer()
    client_handshake_message_bytes = client_framer.frame_handshake(client_private_key,
        server_private_key.public_key)

    async def validate_client_identity(client_identity_public_key: PublicKey) -> Optional[int]:
        return 1

    shared_secret_bytes: Optional[bytes] = None
    async def get_shared_secret(account_id: int, client_identity_public_key: PublicKey,
            message_bytes: bytes) -> bytes:
        nonlocal shared_secret_bytes
        shared_secret_bytes = await get_shared_secret_standard(account_id,
            client_identity_public_key, message_bytes)
        return shared_secret_bytes

    # On the lower edge of the range, should just pass.
    server_framer = PredictableServerFramer()
    server_framer.validate_client_identity = validate_client_identity
    server_framer.get_shared_secret = get_shared_secret
    server_framer.set_timestamp(client_timestamp - core.HANDSHAKE_TIMESTAMP_VARIANCE)
    server_framer.received_bytes(client_handshake_message_bytes)
    await server_framer._receive_handshake_message()

    # On the higher edge of the range, should just pass.
    server_framer = PredictableServerFramer()
    server_framer.validate_client_identity = validate_client_identity
    server_framer.get_shared_secret = get_shared_secret
    server_framer.set_timestamp(client_timestamp + core.HANDSHAKE_TIMESTAMP_VARIANCE)
    server_framer.received_bytes(client_handshake_message_bytes)
    await server_framer._receive_handshake_message()

    # Just over the lower edge of the range, should just fail.
    server_framer = PredictableServerFramer()
    server_framer.validate_client_identity = validate_client_identity
    server_framer.get_shared_secret = get_shared_secret
    server_framer.set_timestamp(client_timestamp + (core.HANDSHAKE_TIMESTAMP_VARIANCE + 1))
    server_framer.received_bytes(client_handshake_message_bytes)
    with pytest.raises(core.AuthenticationError) as e:
        await server_framer._receive_handshake_message()
    assert core.ErrorCodes.INVALID_CLIENT_TIMESTAMP == e.value.args[0]

    # Just over the higher edge of the range, should just fail.
    server_framer = PredictableServerFramer()
    server_framer.validate_client_identity = validate_client_identity
    server_framer.get_shared_secret = get_shared_secret
    server_framer.set_timestamp(client_timestamp + (core.HANDSHAKE_TIMESTAMP_VARIANCE + 1))
    server_framer.received_bytes(client_handshake_message_bytes)
    with pytest.raises(core.AuthenticationError) as e:
        await server_framer._receive_handshake_message()
    assert core.ErrorCodes.INVALID_CLIENT_TIMESTAMP == e.value.args[0]
