from typing import Optional
import unittest

from bitcoinx import int_to_be_bytes, PrivateKey, PublicKey
import pytest

import electrumsv_hosting
from electrumsv_hosting import connection


connection.HandshakeNotification.register()


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


async def get_shared_secret_standard(client_identity_public_key: PublicKey,
        message_bytes: bytes) -> bytes:
    shared_secret_public_key = server_private_key.shared_secret(client_identity_public_key,
        message_bytes)
    return int_to_be_bytes(shared_secret_public_key.to_point()[0])


def test_server_frame_no_handshake() -> None:
    server_framer = connection.ServerFramer()
    with pytest.raises(connection.ConnectionNotEstablishedError):
        server_framer.frame({})


@pytest.mark.asyncio
async def test_handshake_framing() -> None:
    client_message = connection.HandshakeNotification(connection.PROTOCOL_VERSION,
        client_private_key.public_key, client_timestamp, client_nonce_bytes)
    client_message.sign(client_private_key)
    client_packet = connection.Packet(connection.PacketType.NOTIFICATION, client_message)

    client_framer = connection.ClientFramer()
    client_handshake_message_bytes = client_framer.frame(client_packet)

    server_framer = connection.ServerFramer()
    assert not server_framer._handshaken
    server_framer.received_bytes(client_handshake_message_bytes)
    server_packet = await server_framer.receive_message()
    assert client_message.version == server_packet.message.version
    assert client_message.remote_public_key == server_packet.message.remote_public_key
    assert client_message.timestamp == server_packet.message.timestamp
    assert client_message.nonce_bytes == server_packet.message.nonce_bytes
    assert client_message.signature_bytes == server_packet.message.signature_bytes


@pytest.mark.timeout(8)
async def test_handshake_framing_timing_fail() -> None:
    client_message = connection.HandshakeNotification(connection.PROTOCOL_VERSION,
        client_private_key.public_key, client_timestamp, client_nonce_bytes)
    client_message.sign(client_private_key)

    # On the lower edge of the range, should just pass.
    with unittest.mock.patch("electrumsv_hosting.connection.get_timestamp",
            return_value=client_timestamp - connection.HANDSHAKE_TIMESTAMP_VARIANCE):
        client_message.validate()

    # On the higher edge of the range, should just pass.
    with unittest.mock.patch("electrumsv_hosting.connection.get_timestamp",
            return_value=client_timestamp + connection.HANDSHAKE_TIMESTAMP_VARIANCE):
        client_message.validate()

    # Just over the lower edge of the range, should just fail.
    with unittest.mock.patch("electrumsv_hosting.connection.get_timestamp",
            return_value=client_timestamp - (connection.HANDSHAKE_TIMESTAMP_VARIANCE + 1)):
        with pytest.raises(connection.AuthenticationError) as e:
            client_message.validate()
        assert connection.ErrorCodes.INVALID_CLIENT_TIMESTAMP == e.value.args[0]

    # Just over the higher edge of the range, should just fail.
    with unittest.mock.patch("electrumsv_hosting.connection.get_timestamp",
            return_value=client_timestamp + (connection.HANDSHAKE_TIMESTAMP_VARIANCE + 1)):
        with pytest.raises(connection.AuthenticationError) as e:
            client_message.validate()
        assert connection.ErrorCodes.INVALID_CLIENT_TIMESTAMP == e.value.args[0]
