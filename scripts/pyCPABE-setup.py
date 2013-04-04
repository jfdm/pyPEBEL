"""Example script showing how the cpabe scheme provided in the module
can be used as part of a python script.

"""

import argparse
import io
import sys

from charm.toolbox.pairinggroup import PairingGroup

from pebel.util import write_key_to_file
from pebel.cpabe import cpabe_setup


def main():
    """Wrapper programme to generate master key pairs for the
    Bethencourt2007cae CP-ABE Scheme.
    """

    parser = argparse.ArgumentParser(
        description='Generates master '
        'key pairs for the Bethencourt2007cae CP-ABE Scheme.')
    parser.add_argument('--mpk-out',
                        default="cp.mpk",
                        dest='mpk',
                        type=str,
                        help='The name of the file in which to store the '
                        'Public Parameters. Default: %(default)s')

    parser.add_argument('--msk-out',
                        default="cp.msk",
                        dest='msk',
                        type=str,
                        help='The name of the file in which to store the '
                        'Master Secret Key. Default: %(default)s')

    args = parser.parse_args()
    group = PairingGroup('SS512')
    (mpk, msk) = cpabe_setup(group)

    write_key_to_file(args.mpk, mpk, group)
    write_key_to_file(args.msk, msk, group)

if __name__ == '__main__':
    main()
