"""The Predicate Based Encryption Library (Pebel) is a simple python
package that provides 'default' implementations for various
Predicate-Based Encryption schemes.

The implementation of these schemes have been taken from the Charm
Toolkit. Pebel provides a series of wrapper functions, and extensions,
allowing for KEM/DEM use of the schemes within Crypto-Systems. The DEM
scheme is the default AES implementation taken from pyCrypto, using a
randomly generated session key taken from a random group element.

Currently supported schemes are as follows:

 - Ciphertext-Policy Attribute Based Encryption, based upon the
   construction given in Bethencourt2007cae.

 - Key-Policy Attributed Based Encryption, based upon the construction
   given in ...

For each schemes presented, there will be four provide functions:

 1. <name>_setup :: Initialises the crypto-scheme and generates the
    master public and private keys.

 2. <name>_keygen :: Uses the master keys to generate decryption keys.

 3. <name>_encrypt :: Encrypts a plaintext byte array from either an
    io file descriptor in 'b' mode, or byte stream, under the provided
    encryption key.

 4. <name>_decrypt :: Attempts to decrypts a ciphertext byte array
    from either an io file descriptor in 'b' mode, or byte stream,
    using the provided decryption key. If decryption is successful the
    plaintext is returned. If not an L{PebelDecryptionException} is
    raised.

The function parameters will differ according to the schemes. Please
see each modules documentation for more details.

Along side these wrapper functions are a series of python scripts that
can be called from the commmand line to encrypt files to allow
experimentation with PBE schemes. For each supported scheme a script
is provided per function.

"""
