"""This module provides a series of wrapper functions over the deafult
implementation for the Lewko2008rsw Key-Policy Attribute Based
Encryption (KP-ABE) scheme as provided within the Charm Toolkit.

The cryptographic workflow follows the standard KEM/DEM methodology.
The plaintext file is encrypted using an Asymmetric Cipher under a
random session key, and the session key itself is encrypted using
KP-ABE under the provided policy.

The asymmetric encryption is a 256-bit AES Cipher in CFB mode, as
provided by pyCrypto.

The session key is a truncated hash of a randomly selected group
element used within the KP-ABE Scheme.

The IV is a randomly selected vector, of length AES.block_size

The generated ciphertext is a linear combination of:

 1. The IV vector
 2. The size in bytes of the encrypted session key.
 3. The encrypted session key.
 4. The AES encrypted plaintext.

@author: Jan de Muijnck-Hughes <jfdm@st-andrews.ac.uk>

"""

import io
import sys
import struct
import os

from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.core.math.pairing import hashPair as sha

from Crypto.Cipher import AES
from Crypto import Random

from pebel.exceptions import PebelDecryptionException
from pebel.util import (
    write_key_to_file,
    read_key_from_file,
    read_data
)

def kpabe_setup(group):
    """Generates the master key pair for the Lewko2008rsw KP-ABE Scheme.

    @type group: PairingGroup
    @param group: The pairing group used within the underlying crypto.

    @rtype: (pk_t, mk_t)
    @return: The master publix and private key pair as defined within
    KPabe implementaton.
    """
    return KPabe(group).setup()

def kpabe_keygen(group, msk, mpk, policy):
    """
    @type group: PairingGroup
    @param group: The pairing group used within the underlying crypto.

    @type msk: mk_t
    @param msk: The master secret key.

    @type mpk: pk_t
    @param mpk: The master public key.

    @type policy: str
    @param policy: The policy used to generate the decryption key.

    @rtype: (sk_t)
    @return: The generated decryption ket as defined in the KPabe
    implementation.
    """
    return KPabe(group).keygen(mpk, msk, policy)


def kpabe_encrypt(group, mpk, ptxt, attributes):
    """
    @type group: PairingGroup
    @param group: The pairing group used within the underlying crypto.

    @type mpk: mk_t
    @param mpk: The master public key.

    @type ptxt: bytearray
    @param ptxt: The bytearray resulting from io.open or io.IOBytes
    containing the plaintext.

    @type attributes: List[str]
    @param attributes: The set of attributes used to encrypt the
    plaintext.

    @rtype: bytearray
    @return: The encrypted data returned as a byte array.
    """
    kpabe = KPabe(group)

    session_key = group.random(GT)
    session_key_ctxt = kpabe.encrypt(mpk,
                                     session_key,
                                     [a.upper() for a in attributes])
    ctxt = io.BytesIO()

    iv = Random.new().read(AES.block_size)
    symcipher = AES.new(sha(session_key)[0:32], AES.MODE_CFB, iv)

    ctxt.write(bytes(iv))

    session_key_ctxt_b = objectToBytes(session_key_ctxt, group)
    ctxt.write(struct.pack('Q' ,len(session_key_ctxt_b)))
    ctxt.write(session_key_ctxt_b)

    for b in read_data(bin_data=ptxt, chunksize=AES.block_size):
        ctxt.write(symcipher.encrypt(b))
        ctxt.flush()

    return ctxt.getvalue()



def kpabe_decrypt(group, mpk, deckey, ctxt):
    """Decrypts a ciphertext using the Lewmko2008rws KP-ABE Scheme.

    The plaintext will be returned iff the set of attributes used to
    generate the cipher-text can be satisfied by the policy within the
    decryption key.

    @type group: PairingGroup
    @param group: The pairing group used within the underlying crypto.

    @type mpk: mk_t
    @param mpk: The Master Public Key.

    @type deckey: sk_t
    @param deckey: The decryption key.

    @type ctxt: bytearray
    @param ctxt: The byte array resulting from io.open or io.IOBytes
                 containing the ciphertext.

    @rtype: bytearray
    @return: bytearray containing the plaintext.

    @raise: L{PebelDecryptionException} if deckey cannot satisfy the
            policy within the ciphertext.
    """
    kpabe = KPabe(group)

    ptxt = io.BytesIO()

    iv = ctxt.read(AES.block_size)
    session_key_size = struct.unpack('<Q',
                                     ctxt.read(struct.calcsize('Q')))[0]
    session_key_ctxt = bytesToObject(ctxt.read(session_key_size), group)
    session_key = kpabe.decrypt(session_key_ctxt, deckey)

    if session_key:
        symcipher = AES.new(sha(session_key)[0:32], AES.MODE_CFB, iv)
        for b in read_data(bin_data=ctxt, chunksize=AES.block_size):
            ptxt.write(symcipher.decrypt(b))
            ptxt.flush()
        return ptxt.getvalue()
    else:
        raise PebelDecryptionException("Unable to decrypt given ciphertext")
