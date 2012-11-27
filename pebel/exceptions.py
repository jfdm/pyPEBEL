"""
Contains custom exceptions used within Pebel.
"""


class PebelException(Exception):
    """Base class for exceptions within Pebel"""
    pass


class PebelDecryptionException(PebelException):
    """Exception raised for errors during decryption"""
