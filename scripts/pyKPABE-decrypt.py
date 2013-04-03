"""
Decrypts ciphertexts encrypted using the KP-ABE Scheme from
Lewko2008rsw.
"""

import struct
import io
import sys
import argparse

from charm.toolbox.pairinggroup import PairingGroup

from pebel.kpabe import kpabe_decrypt
from pebel.util import read_key_from_file
from pebel.exceptions import PebelDecryptionException

def main():
    """Wrapper function to decrypt a given ciphertext file using the
    Lewko2008rsw KP-ABE Scheme.
    """

    parser = argparse.ArgumentParser(
        description="Decrypts a given ciphertext, with name <fname>.kpabe," +
        " using the provided decryption key.")

    parser.add_argument('--mpk',
                        required=True,
                        dest='mpk',
                        type=str,
                        help="The name of the Public Parameters." +
                        " Default: %(default)s")

    parser.add_argument('--ctxt',
                        required=True,
                        dest='ctxt',
                        type=str,
                        help="The name of the file containing the" +
                        " ciphertext to be decrypted.")

    parser.add_argument('--dkey',
                        required=True,
                        dest='dkey',
                        type=str,
                        help="The name of the file containing the" +
                        " decryption key")

    args = parser.parse_args()

    if not args.ctxt.endswith(".kpabe"):
        print("Ciphertext needs to end with .kpabe")
        sys.exit(-1)

    ptxt_fname = args.ctxt.replace(".kpabe", ".prime")

    group = PairingGroup('MNT224')
    
    mpk = read_key_from_file(args.mpk, group)

    dkey = read_key_from_file(args.dkey, group)

    try:
        raw = kpabe_decrypt(group, mpk, dkey, io.open(args.ctxt, 'rb'))
    except PebelDecryptionException as e:
        print("Unable to decrypt ciphertext: {}".format(e))
        sys.exit(-1)
    else:
        with io.open(ptxt_fname, 'wb') as ptxt:
            for b in raw:
                ptxt.write(bytes(b))
                ptxt.flush()

if __name__ == '__main__':
    main()
