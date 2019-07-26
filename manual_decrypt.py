from __future__ import (absolute_import, division, print_function)

from abc import ABCMeta
from array import array
from base64 import b64encode, b64decode
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


class PBEParameterGenerator(object):
    __metaclass__ = ABCMeta

    @staticmethod
    def pad(block_size, s):
        """
        Pad a string to the provided block size when using fixed block ciphers.

        :param block_size: int - the cipher block size
        :param s: str - the string to pad
        :return: a padded string that can be fed to the cipher
        """
        return s + (block_size - len(s) % block_size) * chr(block_size - len(s) % block_size)

    @staticmethod
    def unpad(s):
        """
        Remove padding from the string after decryption when using fixed block ciphers.

        :param s: str - the string to remove padding from
        :return: the unpadded string
        """
        return s[0:-ord(s[-1])]

    @staticmethod
    def adjust(a, a_off, b):
        """
        Adjusts the byte array as per PKCS12 spec

        :param a: byte[] - the target array
        :param a_off: int - offset to operate on
        :param b: byte[] - the bitsy array to pick from
        :return: nothing as operating on array by reference
        """
        x = (b[len(b) - 1] & 0xff) + (a[a_off + len(b) - 1] & 0xff) + 1

        a[a_off + len(b) - 1] = x & 0xff

        x = x >> 8

        for i in range(len(b) - 2, -1, -1):
            x = x + (b[i] & 0xff) + (a[a_off + i] & 0xff)
            a[a_off + i] = x & 0xff
            x = x >> 8

    @staticmethod
    def pkcs12_password_to_bytes(password):
        """
        Converts a password string to a PKCS12 v1.0 compliant byte array.

        :param password: byte[] - the password as simple string
        :return: The unsigned byte array holding the password
        """
        pkcs12_pwd = [0x00] * (len(password) + 1) * 2

        for i in range(0, len(password)):
            digit = ord(password[i])
            pkcs12_pwd[i * 2] = int(digit >> 8)
            pkcs12_pwd[i * 2 + 1] = int(digit)
        x = array('B', pkcs12_pwd)

        return array('B', pkcs12_pwd)


class PKCS12ParameterGenerator(PBEParameterGenerator):
    """
    Equivalent of the Bouncycastle PKCS12ParameterGenerator.
    """
    __metaclass__ = ABCMeta

    KEY_MATERIAL = 1
    IV_MATERIAL = 2
    MAC_MATERIAL = 3

    SALT_SIZE_BYTE = 8

    def __init__(self, digest_factory):
        super(PBEParameterGenerator, self).__init__()
        self.digest_factory = digest_factory

    def generate_derived_parameters(self, password, salt, iterations, key_size, iv_size):
        """
        Generates the key and iv that can be used with the cipher.

        :param password: str - the password used for the key material
        :param salt: byte[] - random salt
        :param iterations: int - number if hash iterations for key material
        :param key_size: int - key size in bits
        :param iv_size: int - iv size in bits
        :return: key and iv that can be used to setup the cipher
        """
        key_size = int(key_size / 8)
        iv_size = int(iv_size / 8)

        # pkcs12 padded password (unicode byte array with 2 trailing 0x0 bytes)
        password_bytes = PKCS12ParameterGenerator.pkcs12_password_to_bytes(password)

        d_key = self.generate_derived_key(password_bytes, salt, iterations, self.KEY_MATERIAL, key_size)
        if iv_size and iv_size > 0:
            d_iv = self.generate_derived_key(password_bytes, salt, iterations, self.IV_MATERIAL, iv_size)
        else:
            d_iv = None
        return d_key, d_iv

    def generate_derived_key(self, password, salt, iterations, id_byte, key_size):
        """
        Generate a derived key as per PKCS12 v1.0 spec

        :param password: byte[] - pkcs12 padded password (unicode byte array with 2 trailing 0x0 bytes)
        :param salt: byte[] - random salt
        :param iterations: int - number if hash iterations for key material
        :param id_byte: int - the material padding
        :param key_size: int - the key size in bytes (e.g. AES is 256/8 = 32, IV is 128/8 = 16)
        :return: the sha256 digested pkcs12 key
        """

        u = int(self.digest_factory.digest_size)
        v = int(self.digest_factory.block_size)

        d_key = [0x00] * key_size

        # Step 1
        D = [id_byte] * v

        # Step 2
        S = []
        if salt and len(salt) != 0:
            s_size = v * int((len(salt) + v - 1) / v)
            S = [0x00] * s_size

            salt_size = len(salt)
            for i in range(s_size):
                S[i] = salt[i % salt_size]

        # Step 3
        P = []
        if password and len(password) != 0:
            p_size = v * int((len(password) + v - 1) / v)
            P = [0x00] * p_size

            password_size = len(password)
            for i in range(p_size):
                P[i] = password[i % password_size]

        # Step 4
        I = array('B', S + P)
        B = array('B', [0x00] * v)

        # Step 5
        c = int((key_size + u - 1) / u)

        # Step 6
        for i in range(1, c + 1):
            # Step 6 - a
            digest = self.digest_factory.new()
            digest.update(array('B', D))
            digest.update(I)
            A = array('B', digest.digest())  # bouncycastle now resets the digest, we will create a new digest

            for j in range(1, iterations):
                A = array('B', self.digest_factory.new(A).digest())

                # Step 6 - b
            for k in range(0, v):
                B[k] = A[k % u]

            # Step 6 - c
            for j in range(0, int(len(I) / v)):
                self.adjust(I, j * v, B)

            if i == c:
                for j in range(0, key_size - ((i - 1) * u)):
                    d_key[(i - 1) * u + j] = A[j]
            else:
                for j in range(0, u):
                    d_key[(i - 1) * u + j] = A[j]

        return array('B', d_key)

def get_params(passphrase, salt, iterations=19, key_len=256, iv_len=128):
    pass

def decrypt(password, ciphertext, iterations=19):
    # some default from somewhere
    key_size_bits = 256
    iv_size_bits = 128

    # create sha256 PKCS12 secret generator
    generator = PKCS12ParameterGenerator(SHA256)

    # decode the base64 encoded and encrypted secret
    n_cipher_bytes = b64decode(ciphertext)

    # extract salt bytes 0 - SALT_SIZE
    #salt = array('B', n_cipher_bytes[:PKCS12ParameterGenerator.SALT_SIZE_BYTE])
    salt = array('B', 'A99BC8325635E303'.decode('hex'))
    # print('dec-salt = %s' % binascii.hexlify(salt))

    # create reverse key material
    key, iv = generator.generate_derived_parameters(password, salt, iterations, key_size_bits, iv_size_bits)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    # extract encrypted message bytes SALT_SIZE - len(cipher)
    #n_cipher_message = array('B', n_cipher_bytes[PKCS12ParameterGenerator.SALT_SIZE_BYTE:])
    n_cipher_message = array('B', n_cipher_bytes)

    # decode the message and unpad
    decoded = cipher.decrypt(n_cipher_message.tostring())

    return generator.unpad(decoded)


if __name__ == "__main__":
    passcode = '2M#84->)y^%2kGmN97ZLfhbL|-M:j?'
    #result = encrypt(passcode, 'secret value', 19)

    #print('enc = %s' % result)

    ciphertext = 'E0px0HwYQkhCCSxPYH2L+PlHjBNl8SG+6HaiRhhkEWe3XGb16tI5LDUGPpRDKuKtbxGz4xu/1anStV+EQS4h/Q=='
    reverse = decrypt(passcode, result, 19)

    print('[+] Decrypted: %s' % reverse)

    # run something like this on the jasypt command line
    # $JASYPT_HOME/bin/decrypt.sh keyObtentionIterations = 4000 \
    #                             providerClassName = "org.bouncycastle.jce.provider.BouncyCastleProvider" \
    #                             saltGeneratorClassName = "org.jasypt.salt.RandomSaltGenerator" \
    #                             algorithm = "PBEWITHSHA256AND256BITAES-CBC-BC" \
    #                             password = 'pssst...don\'t tell anyone' \
    #                             input = 'xgX5+yRbKhs4zSubkAPkg9gSBkZU6XWt7csceM/3xDY='
