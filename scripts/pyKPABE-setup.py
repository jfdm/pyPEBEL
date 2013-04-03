"""Example script demonstrating how the kpabe scheme provided within
the module can be used as part of a python script.
"""

import argparse
import io
import sys

from charm.toolbox.pairinggroup import PairingGroup

from pebel.util import write_key_to_file
from pebel.kpabe import kpabe_setup


def main():
    """Wrapper programme to generate master key pairs for the
    Lewko2008rsw KP-ABE Scheme.
    """

    parser = argparse.ArgumentParser(
        description='Generates master key '
        'pairs for the Lewko2008rsw KP-ABE Scheme.')
    parser.add_argument('--mpk-out',
                        default="kp.mpk",
                        dest='mpk',
                        type=str,
                        help='The name of the file in which to store the '
                        'Public Parameters. Default: %(default)s')

    parser.add_argument('--msk-out',
                        default="kp.msk",
                        dest='msk',
                        type=str,
                        help='The name of the file in which to store the '
                        'Master Secret Key. Default: %(default)s')

    args = parser.parse_args()
    group = PairingGroup('MNT224')
    (mpk, msk) = kpabe_setup(group)

    write_key_to_file(args.mpk, mpk, group)
    write_key_to_file(args.msk, msk, group)

if __name__ == '__main__':
    main()
