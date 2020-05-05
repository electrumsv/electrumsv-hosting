Hosted Mailbox
==================================
The mailbox server takes connections from clients via WP42 tunnel and facilitates the delivery of encrypted messages
to one of their contacts.

These messages can be delivered to the recipient by:

    a) depositing them in the mailbox for later (the fallback option)
    b) direct, p2p communication (initially facilitated by the server)

In either case, the headers, payloads and messaging protocol are the same for both peers.


Public Identity Registration
#####################################

register_identity
******************
This endpoint is an exception to the rule in that no headers, signatures or authentication
are required because an alias and identity public key are required for those things.

It registers an alias to the server with a designated identity pubkey.
A security challenge must be completed, proving control of the identity pubkey
(e.g. signing a recent unix timestamp - within the last 60 minutes).


Overview of Headers and Payloads
################################
All other endpoints (besides public identity registration) are either:

    - **'Client-Server' endpoints** (tunnelled to server but unencrypted payload)
    - **'Mailbox' messages** (tunnelled to server *and* encrypted payload with wp42 derived shared secret for the p2p relationship)

Headers
*******
The standardized header is always the same. For some endpoints the receiver_pubkey
is omitted (e.g. get_id_key, subscribe_to_messagebox, get_message

.. code-block:: python

    'sender_pubkey'
    'receiver_pubkey' (only applicable for mailbox messages) - hex
    'sender_nonce'  (8 byte nonce) - hex
    'payload_hash'  (of utf-8 encoded ciphertext) hex
    'sender_signature' (signs the above 4 fields - base64 encoded)


For authentication between client and server the sender signature covers the sender_pubkey, sender_nonce, payload_hash
but **not** the receiver_pubkey for sake of uniformity (receiver_pubkey is not always included).

Payload
*******
Base64 encoded json +/- encryption (for Mailbox endpoints)

Client-Server Endpoints
#######################

get_id_key
************
Get an identity pubkey for a given human-readable alias

subscribe_to_messagebox
***********************
Returns an integer ('message_id') that increments for each additional message to a given identity pubkey.
The client can then reconcile any missed messages while offline or maintain a real-time feed of inbound messages.

get_message
***********
Takes the message_id from the 'subscribe_to_messagebox' endpoint and returns the full message with header and payload.


Mailbox Messages
###########################
There is **one endpoint** server-side:

    'send_message',

This is the most interesting endpoint because there can be many different message types embedded in the encrypted
payload. There could be many alternative p2p protocols co-existing with this service - we do not discriminate.

The takeaway is that the payloads are encrypted with a shared secret between the two peers. The server is not privy
to any information contained in the message payload. As such there is minimal risk for clients and minimal liability
for the service provider.

send_message
************
Below are several example message types (agreed to between two peers) - centered around using the well
recognised w3c identity-protocols_ for DID_ and verifiable credentials_ as well as BIP270_ for p2p payments

.. _identity-protocols: https://w3c.github.io/did-core/
.. _DID: https://w3c.github.io/did-core/
.. _credentials: https://w3c.github.io/vc-data-model/
.. _BIP270: https://github.com/moneybutton/bips/blob/master/bip-0270.mediawiki

^^^^^^^^^^^^^^
message types:
^^^^^^^^^^^^^^

contact_request
---------------
We do not wish to impose our own implementation. However, I imagines this payload to
include something like:

.. code-block:: python

    - message_type: 'contact_request'
    - sender DID document (see https://w3c.github.io/did-core/) - namely on-chain identity pubkey
    - sender VCs (proof of identity - see https://w3c.github.io/vc-data-model/)
    - sender IPv4/6 address/port - Optional (and whatever else is needed for direct p2p communication)

The nonce of a contact_request **header** holds special significance. Every new message uses the next nonce
in the sequence (rehashing this landmark nonce N times for the Nth message of the p2p relationship).
This nth hash is then used for shared secret derivation and encryption.
As per the WP0042 spec.

    1) contact_request *encrypts* using V2C and P2S -> S
    2) receiver *decrypts* with the same shared secret via V2S and P2C -> S

The sequence continues (As per the WP0042 spec - V1: Hierarchy of Hashes):

    3) contact_request *encrypts* using V2C' and P2S' -> S
    4) receiver *decrypts* with the same shared secret via V2S' and P2C' -> S

... and so on to V2C'' and V2C''' etc. **re-hashing the original nonce N times to get to the
Nth set of keys**

The advantage of this approach rather than using a fresh nonce every time is to do with on-chain
backup solutions. With the 'Hierarchy of Hashes' approach, everything that is required for
full disaster-recovery is contained within the 1st exchange of contact information.

Furthermore, the overall model of establishing payment scripts this way sidesteps the problems
with the current paymail/bsvalias implementation of having a server that **takes responsibility
(along with the liability of running a secure service) for giving out correct Bip32-derived
payment scripts/pubpkeys**. So as I see it, there are only benefits and no downsides to shifting
this responsibility to rest solely in the hands of the two peers.


contact_response
----------------
The same as the received :code:`'contact_request'` message - from which ongoing p2p or mailbox-based communication
can continue.

send_transaction
------------------------------
A raw, signed bitcoin transaction only

send_payment_request (bip270)
-----------------------------
see https://github.com/moneybutton/bips/blob/master/bip-0270.mediawiki

send_payment (bip270)
----------------------
see https://github.com/moneybutton/bips/blob/master/bip-0270.mediawiki

send_payment_ack (bip270)
-------------------------
see https://github.com/moneybutton/bips/blob/master/bip-0270.mediawiki
