"""This module provides a series of wrapper functions over the default
implementation for the Bethencourt2007cae Ciphertext-Policy Attribute
Based Encryption (CP-ABE) scheme as provided within the Charm Toolkit.

The cryptographic workflow follows the standard KEM/DEM methodology.
The plaintext file is encrypted using an Asymmetric Cipher under a
random session key, and the session key itself is encrypted using
CP-ABE under the provided policy.

The asymmetric encryption is a 256-bit AES Cipher in CFB mode, as
provided by pyCrypto.

The session key is a truncated hash of a randomly selected group
element used within the CP-ABE Scheme.

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
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
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


def cpabe_setup(group):
    """Generates master key pair for the Bethencourt2007cae CP-ABE Scheme.

    @type group: PairingGroup
    @param group: The pairing group used within the underlying crypto.

    @rtype: (pk_t, mk_t)
    @return: The master public and private key pair as defined in the
             CPabe_BSW07 Scheme.
    """
    return CPabe_BSW07(group).setup()


def cpabe_keygen(group, msk, mpk, attributes):
    """Generates a decryption key pair for the Bethencourt2007cae
    CP-ABE Scheme.

    @type group: PairingGroup
    @param group: The pairing group used within the underlying crypto.

    @type msk: mk_t
    @param msk: The Master Secret Key.

    @type mpk: pk_t
    @param mpk: The Master Public Key.

    @type attributes: List[str]
    @param attributes: The set of attributes used to generate the
    decryption key.

    @rtype: (sk_t)
    @return: The generated decryption key as defined in
             the CPabe_BSW07 Scheme.

    """
    return CPabe_BSW07(group).keygen(mpk, msk, attributes)


def cpabe_encrypt(group, mpk, ptxt, policy):
    """Encrypts a plain-text using the Bethencourt2007cae CP-ABE Scheme.

    @type group: PairingGroup
    @param group: The pairing group used within the underlying crypto.

    @type mpk: mk_t
    @param mpk: The master public key.

    @type ptxt: bytearry
    @param ptxt: The byte array resulting from io.open or io.IOBytes
                 containing the plaintext.

    @type policy: str
    @param policy: The policy used to encrypt the plaintext.

    @rtype: bytearray
    @return: The encrypted data returned as a byte array.

    """
    cpabe = CPabe_BSW07(group)

    session_key = group.random(GT)
    session_key_ctxt = cpabe.encrypt(mpk, session_key, policy)

    ctxt = io.BytesIO()

    iv = Random.new().read(AES.block_size)
    symcipher = AES.new(sha(session_key)[0:32], AES.MODE_CFB, iv)

    ctxt.write(bytes(iv))

    session_key_ctxt_b = objectToBytes(session_key_ctxt, group)
    ctxt.write(struct.pack('<Q', len(session_key_ctxt_b)))
    ctxt.write(session_key_ctxt_b)

    for b in read_data(bin_data=ptxt, chunksize=AES.block_size):
        ctxt.write(symcipher.encrypt(b))
        ctxt.flush()

    return ctxt.getvalue()


def cpabe_decrypt(group, mpk, deckey, ctxt):
    """Decrypts a ciphertext using the Bethencourt2007cae CP-ABE Scheme.

    The plaintext will be returned iff the policy used to generate the
    cipher-text can be satisfied by the set of attributes within the
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
    cpabe = CPabe_BSW07(group)
    ptxt = io.BytesIO()

    iv = ctxt.read(AES.block_size)
    session_key_size = struct.unpack('<Q', ctxt.read(struct.calcsize('Q')))[0]
    session_key_ctxt = bytesToObject(ctxt.read(session_key_size), group)

    session_key = cpabe.decrypt(mpk,deckey, session_key_ctxt)

    if session_key:
        symcipher = AES.new(sha(session_key)[0:32], AES.MODE_CFB, iv)
        for b in read_data(bin_data=ctxt, chunksize=AES.block_size):
            ptxt.write(symcipher.decrypt(b))
            ptxt.flush()
        return ptxt.getvalue()
    else:
        raise PebelDecryptionException("Unable to decrypt given cipher-text.")
