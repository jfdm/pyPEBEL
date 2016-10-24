"""Encrypts data using the CP-ABE from Bethencourt2007cae.

"""

import argparse
import io
import sys
import struct
import os

from charm.toolbox.pairinggroup import PairingGroup

from pebel.cpabe import cpabe_encrypt
from pebel.util import read_key_from_file


def main():
    """Wrapper function to encrypt a file using the Bethencourt2007cae
    CP-ABE Scheme.

    """

    parser = argparse.ArgumentParser(
        description="Encrypts a named file under a given policy using the" +
        " BSW2007cae CP-ABE Scheme.")

    parser.add_argument('--mpk',
                        required=True,
                        dest='mpk',
                        type=str,
                        help="The name of the Public Parameters."+
                        " Default: %(default)s")

    parser.add_argument('--ptxt',
                        required=True,
                        dest='ptxt',
                        type=str,
                        help="A file containing the plaintext to be encrypted.")

    parser.add_argument('policy',
                        help="The policy used to encrypt the plaintext under.")

    args = parser.parse_args()

    group = PairingGroup('SS512')

    mpk = read_key_from_file(args.mpk, group)

    ctxt = cpabe_encrypt(group, mpk, io.open(args.ptxt,'rb'), args.policy)

    ctxt_fname = "".join([args.ptxt, ".cpabe"])

    with io.open(ctxt_fname, 'wb') as ctxt_file:
        for b in ctxt:
            ctxt_file.write(bytes([b]))


if __name__ == '__main__':
    main()
