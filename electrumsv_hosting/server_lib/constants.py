from bitcoinx import PublicKey, PrivateKey

SERVER_PRIVATE_KEY_BYTES = bytes.fromhex(
    '6feba37e2c41c1caf6a2e6ee45e432da43d5eb34b61951df2833fe47bfbf65af')
SERVER_PRIVATE_KEY = PrivateKey(SERVER_PRIVATE_KEY_BYTES)
SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.public_key

ALICE_TEST_ALIAS = "Alice1234"
ALICE_TEST_IDENTITY_PRIVATE_KEY_BYTES = bytes.fromhex(
    "de9b67751d0d208cd3cf6ad5d2e3b9aa88036af4e4f76952f730e388abe69400")
ALICE_TEST_IDENTITY_PRIVATE_KEY = PrivateKey(ALICE_TEST_IDENTITY_PRIVATE_KEY_BYTES)
ALICE_TEST_IDENTITY_PUBLIC_KEY = ALICE_TEST_IDENTITY_PRIVATE_KEY.public_key

BOB_TEST_ALIAS = "Bob2468"
BOB_TEST_IDENTITY_PRIVATE_KEY_BYTES = bytes.fromhex(
    "a2d9803c912ab380c1491d3bd1aaab34ca06742d7885a224ec8d386182d26ed2")
BOB_TEST_IDENTITY_PRIVATE_KEY = PrivateKey(BOB_TEST_IDENTITY_PRIVATE_KEY_BYTES)
BOB_TEST_IDENTITY_PUBLIC_KEY = BOB_TEST_IDENTITY_PRIVATE_KEY.public_key


BITCOIN_NETWORK_VARNAME = 'network'
DATABASE_NAME_VARNAME = 'database_name'
DATABASE_USER_VARNAME = 'database_username'
DATABASE_HOST_VARNAME = 'database_host'
DATABASE_PORT_VARNAME = 'database_port'
DATABASE_PASSWORD_VARNAME = 'database_password'
LOGGING_LEVEL_VARNAME = 'logging_level'


class Errors:
    ALIAS_PUBKEY_NOT_FOUND_CODE = 404000
    ALIAS_PUBKEY_NOT_FOUND_MESSAGE = "Alias pubkey not found"
