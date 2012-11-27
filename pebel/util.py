"""
Various utility methods to read and write, data from buffers and files.
"""

import string
import io
from charm.toolbox.pairinggroup import PairingGroup
from charm.core.engine.util import objectToBytes, bytesToObject


def write_key_to_file(fname, data, group):
    """Utility function to save charm crypto objects to disk.

    @type fname: str
    @param fname: The name of the file to save the data to.

    @type data: ByteArray
    @param data: The data to be saved.

    @type group: PairingGroup
    @param group: The group used within the underlying crypto.

    """
    with io.open(fname, 'wb') as f:
        f.write(objectToBytes(data, group))
        f.flush()


def read_key_from_file(fname, group):
    """Utility function to read charm crypto objects from disk.

    @type fname: str
    @param fname: The name of the file containing the keys.

    @type group: PairingGroup
    @param group: The pairing group used within the underlying crypto.

    @return: An object reconstructed from the file.
    """
    with io.open(fname, 'rb') as f:
        data = f.read()
    return bytesToObject(data, group)

def bitmarker(name, nbits, pos, v):
    """Construct a bit marker for a bit within a bit string.

    @type name: str
    @param name: The name of the attribute.

    @type nbits: int
    @param nbits: The word size used to represent integers.

    @type pos: int
    @param pos: The position of the bit (from lsb) of the bit within
    the bit string.

    @type v: int
    @param v: The int representation of bit value i.e. '1' or '0'.

    @rtype: str
    @return: The bit marker for the bit.
    """
    l = string.rjust('', nbits - pos - 1 , 'x')
    r = string.ljust('', pos, 'x')
    return "{0}:{1}{2}{3}".format(name,l,v,r)


def read_data(bin_data, chunksize=16):
    """Utility function to read binary data in chunks.

    The bin_data should be the result of a call to io.open or
    io.BytesIO containing the data to be read. Each invocation of
    read_data shall read in a single chunk of data, where chunk is a
    predefined size. The default chunk size is: 16 bytes.

    @type bin_data: ByteArray
    @param bin_data: A bytearray to be read.

    @type chunksize: int
    @param chunksize: The size of chunks to read.

    @return: Each call returns a single chunk of data from the byte
    array.

    """
    with bin_data as src:
        while True:
            data = src.read(chunksize)
            if data:
                yield data
            else:
                break
