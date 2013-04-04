"""Generates a decryption key using CP-ABE as defined within Bethencourt2007cae.

"""

import argparse
import io
import sys

from charm.toolbox.pairinggroup import PairingGroup

from pebel.cpabe import cpabe_keygen
from pebel.util import (
    write_key_to_file,
    read_key_from_file
)




def main():
    """Wrapper function to generate decryption keys for the
    Bethencourt2007cae CP-ABE Scheme.
    """
    parser = argparse.ArgumentParser(
        description="Generates decryption keys from a set of attributes" +
        " for the BSW2007cae CP-ABE Scheme.")
    parser.add_argument('--mpk',
                        required=True,
                        dest='mpk',
                        type=str,
                        help="The name of the Public Parameters." +
                        " Default: %(default)s")
    parser.add_argument('--msk',
                        required=True,
                        dest='msk',
                        type=str,
                        help="The name of the Master Secret Key." +
                        " Default: %(default)s")
    parser.add_argument('--dkey-out',
                        default="bob.cp.dkey",
                        dest='dkey',
                        type=str,
                        help="The name of the file in which to store" +
                        " the decryption key. Default: %(default)s")
    parser.add_argument('attributes',
                        nargs=argparse.REMAINDER,
                        help="The attributes used to construct the secret key.")

    args = parser.parse_args()
    group = PairingGroup('SS512')
    msk = read_key_from_file(args.msk, group)
    mpk = read_key_from_file(args.mpk, group)

    attributes = [a.upper() for a in args.attributes]

    dec_key = cpabe_keygen(group, msk, mpk, attributes)

    write_key_to_file(args.dkey, dec_key, group)

if __name__ == '__main__':
    main()
