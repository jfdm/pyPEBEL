"""
Generates a decryption key using KP-ABE as defined within Lewko2008rsw.
"""

import argparse
import io
import sys

from charm.toolbox.pairinggroup import PairingGroup

from pebel.kpabe import kpabe_keygen
from pebel.util import (
    write_key_to_file,
    read_key_from_file
)


def main():
    """Wrapper function to generate decryption keys for the
    Lewko2008rsw KP-ABE Scheme."""

    parser = argparse.ArgumentParser(
        description="Generates decryption keys from a policy" +
        " for the Lewko2008rsw KP-ABE Scheme.")
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
                        default="bob.kp.dkey",
                        dest='dkey',
                        type=str,
                        help="The name of the file in which to store" +
                        " the decryption key. Default: %(default)s")
    parser.add_argument('policy',
                        help="The policy used to construct the secret key.")

    args = parser.parse_args()
    group = PairingGroup('MNT224')
    msk = read_key_from_file(args.msk, group)
    mpk = read_key_from_file(args.mpk, group)

    dec_key = kpabe_keygen(group, msk, mpk, args.policy)

    write_key_to_file(args.dkey, dec_key, group)

if __name__ == '__main__':
    main()
