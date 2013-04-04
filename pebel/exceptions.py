"""@package pebel.exceptions

Contains custom exceptions used within pyPEBEL.
"""


class PebelException(Exception):
    """Base class for exceptions within Pebel"""
    pass


class PebelDecryptionException(PebelException):
    """Raised for errors during decryption"""
    pass
    
