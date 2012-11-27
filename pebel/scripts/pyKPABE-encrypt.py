"""
Encrypts data using the KP-ABE from Lewko2008rsw.
"""

import io
import sys
import struct
import os
import argparse

from charm.toolbox.pairinggroup import PairingGroup

from pebel.kpabe import kpabe_encrypt
from pebel.util import read_key_from_file



def main():
    """Wrapper function to encrypt a file using the
    Lewko2008rsw KP-ABE Scheme.
    """

    parser = argparse.ArgumentParser(
        description="Encrypts a named file under a given set of attributes"
        " using the Lewko2008rsw KP-ABE Scheme."
        )

    parser.add_argument('--mpk',
                        required=True,
                        dest='mpk',
                        type=str,
                        help="The name of the public parameters"
                        " Default: %(default)s"
        )

    parser.add_argument('--ptxt',
                        required=True,
                        dest='ptxt',
                        type=str,
                        help="A file containing the plaintext to be encrypted."
        )

    parser.add_argument('attributes',
                        nargs=argparse.REMAINDER,
                        help="The attributes used to encrypt the plain-text"
        )

    args = parser.parse_args()

    group = PairingGroup('MNT224')

    mpk = read_key_from_file(args.mpk, group)

    ctxt = kpabe_encrypt(group, mpk, io.open(args.ptxt, 'rb'), args.attributes)

    ctxt_fname = "".join([args.ptxt, ".kpabe"])

    with io.open(ctxt_fname, 'wb') as ctxt_file:
        for b in ctxt:
            ctxt_file.write(bytes(b))
            

if __name__ == '__main__':
    main()
