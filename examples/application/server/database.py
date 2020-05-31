import datetime
from typing import Optional

from bitcoinx import PublicKey
import peewee
from peewee import (AutoField, BlobField, CharField, CompositeKey, DateTimeField, DoesNotExist,
    ForeignKeyField, IntegerField, Model, PostgresqlDatabase)

from .constants import DATABASE_NAME_VARNAME, \
    DATABASE_USER_VARNAME, DATABASE_HOST_VARNAME, DATABASE_PORT_VARNAME, DATABASE_PASSWORD_VARNAME


db = PostgresqlDatabase(None)


class BaseModel(Model):
    class Meta:
        database = db


class Identity(BaseModel):
    identity_pubkey = CharField(max_length=66, unique=True)  # hex
    date_created = DateTimeField(default=datetime.datetime.now)


class IdentityMessage(BaseModel):
    message_id = IntegerField()
    date_created = DateTimeField(default=datetime.datetime.now)
    receiver_pubkey = CharField(max_length=66)
    sender_timestamp = DateTimeField()
    sender_nonce = BlobField()
    sender_signature = CharField()
    payload_hash = BlobField()
    payload = BlobField()  # base_64_encoded ciphertext
    identity = ForeignKeyField(Identity, backref="messages")

    class Meta:
        primary_key = CompositeKey("identity", "message_id")


class DatabaseAPI:
    def create_identity(self, identity_pubkey: PublicKey) -> int:
        # pylint: disable=no-value-for-parameter
        return Identity.insert(identity_pubkey=identity_pubkey.to_hex()).execute()

    def get_id_for_identity(self, identity_pubkey: PublicKey) -> Optional[int]:
        try:
            return Identity.select(Identity.id).where(
                Identity.identity_pubkey == identity_pubkey.to_hex()).get().id
        except Identity.DoesNotExist:
            return None

    def insert_message(self, identity_id: int, receiver_pubkey: PublicKey, sender_timestamp: int,
            sender_nonce: bytes, sender_signature: str, payload_hash: bytes, payload: bytes) \
                -> None:
        latest_message_id = self.get_latest_message_id(identity_id)
        message_id = latest_message_id + 1
        # pylint: disable=no-value-for-parameter
        IdentityMessage.insert(identity = identity_id,
            message_id = message_id,
            receiver_pubkey = receiver_pubkey.to_hex(),
            sender_timestamp = sender_timestamp,
            sender_nonce = sender_nonce,
            sender_signature = sender_signature,
            payload_hash = payload_hash,
            payload = payload).execute()
        return message_id

    def get_latest_message_id(self, identity_id: int) -> int:
        message_id = (IdentityMessage
            .select(peewee.fn.MAX(IdentityMessage.message_id))
            .join(Identity)
            .where(IdentityMessage.identity.id == identity_id).scalar())
        return 0 if message_id is None else message_id

    def get_message(self, identity_id: int, message_id: int) -> IdentityMessage:
        return (IdentityMessage
            .select()
            .join(Identity)
            .where(IdentityMessage.message_id == message_id &
                IdentityMessage.identity.id == identity_id)
            .get())


def load(config) -> PostgresqlDatabase:
    database_name = config[DATABASE_NAME_VARNAME]
    database_user = config[DATABASE_USER_VARNAME]
    host = config[DATABASE_HOST_VARNAME]
    port = config[DATABASE_PORT_VARNAME]
    password = config[DATABASE_PASSWORD_VARNAME]

    db.init(database=database_name, user=database_user, host=host, port=port, password=password)
    db.connect()
    db.drop_tables([Identity, IdentityMessage], safe=True)  # Todo - remove when finished testing
    db.create_tables([Identity, IdentityMessage], safe=True)
    db.close()
    return db


MAX_VARS = 999
