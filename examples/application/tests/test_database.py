import datetime
import os

from bitcoinx import PrivateKey, PublicKey
from electrumsv_hosting.utils import get_nonce
import pytest

from server.constants import (DATABASE_NAME_VARNAME, DATABASE_USER_VARNAME, DATABASE_HOST_VARNAME,
    DATABASE_PORT_VARNAME, DATABASE_PASSWORD_VARNAME)
from server import database


database_config = {
    DATABASE_NAME_VARNAME: "mailboxdb",
    DATABASE_USER_VARNAME: "mailboxadmin",
    DATABASE_HOST_VARNAME: "127.0.0.1",
    DATABASE_PORT_VARNAME: 5432,
    DATABASE_PASSWORD_VARNAME: "mailboxpassword",
}

sample_prvkey1 = PrivateKey(os.urandom(32))
sample_pubkey1 = sample_prvkey1.public_key
sample_prvkey2 = PrivateKey(os.urandom(32))
sample_pubkey2 = sample_prvkey2.public_key


@pytest.fixture
def db():
    return database.load(database_config)


def test_api_create_identity(db) -> None:
    api = database.DatabaseAPI()
    identity_id = api.create_identity(sample_pubkey1)
    assert identity_id == 1
    identity_id = api.create_identity(sample_pubkey2)
    assert identity_id == 2

def test_api_get_id_for_identity(db) -> None:
    api = database.DatabaseAPI()
    identity_id = api.create_identity(sample_pubkey1)
    assert identity_id == api.get_id_for_identity(sample_pubkey1)

def test_api_get_latest_message_id(db) -> None:
    api = database.DatabaseAPI()
    identity_id = api.create_identity(sample_pubkey1)
    message_id = api.get_latest_message_id(identity_id)
    assert 0 == message_id

def test_api_insert_message(db) -> None:
    api = database.DatabaseAPI()
    identity_id1 = api.create_identity(sample_pubkey1)
    message_id1 = api.insert_message(identity_id1, sample_pubkey1, datetime.datetime.now(),
        get_nonce(), 'x'*20, os.urandom(8), os.urandom(32))
    assert 1 == message_id1
    assert 1 == api.get_latest_message_id(identity_id1)

    identity_id2 = api.create_identity(sample_pubkey2)
    message_id2 = api.insert_message(identity_id2, sample_pubkey1, datetime.datetime.now(),
        get_nonce(), 'x'*20, os.urandom(8), os.urandom(32))
    assert 1 == message_id2
    assert 1 == api.get_latest_message_id(identity_id2)
