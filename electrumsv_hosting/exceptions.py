import aiorpcx


class ConnectionNotEstablishedError(Exception):
    pass


# These exceptions happen in the aiorpcx RPCSession `_process_messages` message processing.
class AuthenticationError(aiorpcx.ProtocolError):
    pass
