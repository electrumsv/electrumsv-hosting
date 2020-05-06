from peewee import (PostgresqlDatabase, Model, CharField, DateTimeField, BlobField, AutoField)

from .constants import DATABASE_NAME_VARNAME, \
    DATABASE_USER_VARNAME, DATABASE_HOST_VARNAME, DATABASE_PORT_VARNAME, DATABASE_PASSWORD_VARNAME


db = PostgresqlDatabase(None)


class BaseModel(Model):
    class Meta:
        database = db


class Identity(BaseModel):
    identity_pubkey = CharField(max_length=66)  # hex


class Message(BaseModel):
    message_id = AutoField(primary_key=True)
    sender_pubkey = CharField(max_length=66)
    receiver_pubkey = CharField(max_length=66)
    sender_nonce = BlobField()
    sender_signature = CharField()
    date_created = DateTimeField()
    payload = BlobField()  # base_64_encoded ciphertext


def load(config) -> PostgresqlDatabase:
    database_name = config[DATABASE_NAME_VARNAME]
    database_user = config[DATABASE_USER_VARNAME]
    host = config[DATABASE_HOST_VARNAME]
    port = config[DATABASE_PORT_VARNAME]
    password = config[DATABASE_PASSWORD_VARNAME]

    db.init(database=database_name, user=database_user, host=host, port=port, password=password)
    db.connect()
    db.drop_tables([Identity, Message], safe=True)  # Todo - remove when finished testing
    db.create_tables([Identity, Message], safe=True)
    db.close()
    return db


MAX_VARS = 999
