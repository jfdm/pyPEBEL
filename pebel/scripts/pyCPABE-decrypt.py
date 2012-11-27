"""Decrypts ciphertexts encrypted using the CP-ABE Scheme from
Bethencourt2007cae.

"""

import struct
import io
import sys
import argparse

from charm.toolbox.pairinggroup import PairingGroup

from pebel.cpabe import cpabe_decrypt
from pebel.util import read_key_from_file
from pebel.exceptions import PebelDecryptionException

def main():
    """Wrapper function to decrypt a ciphertext file using the
    Bethencourt2007cae CP-ABE Scheme.

    """

    parser = argparse.ArgumentParser(
        description="Decrypts a given ciphertext, with name <fname>.cpabe,"
        " using the provided decryption key.")

    parser.add_argument('--mpk',
                        required=True,
                        dest='mpk',
                        type=str,
                        help="The name of the Public Parameters."+
                        " Default: %(default)s")

    parser.add_argument('--ctxt',
                        required=True,
                        dest='ctxt',
                        type=str,
                        help= "The name of the file containing the" +
                        " ciphertext to be decrypted.")

    parser.add_argument('--dkey',
                        required=True,
                        dest='dkey',
                        type=str,
                        help="The name of the file containing the" +
                        " decryption key")

    args = parser.parse_args()

    if not args.ctxt.endswith(".cpabe"):
        print "Ciphertext needs to end with .cpabe"
        sys.exit(-1)

    ptxt_fname = args.ctxt.replace(".cpabe", ".prime")

    group = PairingGroup('SS512')

    mpk = read_key_from_file(args.mpk, group)

    dkey = read_key_from_file(args.dkey, group)

    try:
        raw = cpabe_decrypt(group, mpk, dkey, io.open(args.ctxt, 'rb'))
    except PebelDecryptionException as e:
        print "Unable to decrypt ciphertext: {}".format(e)
        sys.exit(-1)
    else:
        with io.open(ptxt_fname, 'wb') as ptxt:
            for b in raw:
                ptxt.write(bytes(b))
                ptxt.flush()

if __name__ == '__main__':
    main()
