#!/usr/bin/python3
"""
Peyk Secure Encrypted Messenger
GNU AGPL 3.0 Licensed
Copyright (C) 2018 17London78 Inc.
=========================================
"""
__author__ = "Mohammad Mahdi Baghbani Pourvahid"
__copyright__ = "Copyright (C) 2018 17London78 Inc."
__credits__ = ["Jadi Mirmirani", "Xysun", "Al Sweigart"]
__license__ = "AGPL 3.0"
__maintainer__ = "Mohammad Mahdi Baghbani Pourvahid"
__email__ = "MahdiBaghbani@Protonmail.com"
__version__ = "0.1-beta"
__status__ = "Development"

from collections import namedtuple
from ..Ciphers import RSA, AES
from ..Assets import BasicFunctions


class Cipher:
    """A base class for authenticated encryption and decryption"""

    def __init__(self, username, pub_key, priv_key, priv_key_password, receiver_pub_key):
        self.username = username
        self.pub_key = pub_key
        self.priv_key = priv_key
        self.priv_key_password = priv_key_password
        self.receiver_pub_key = receiver_pub_key
        self.sign = 'LSAssp'
        self.enc_state = None

    def _rsa_encrypt(self, key_tuple, key_dict=None):
        aes_key_dictionary = dict()
        if key_dict is None:
            clients = list(self.receiver_pub_key.keys())
            for client in clients:
                pub_key = self.receiver_pub_key[client]
                aes_key_dictionary[client] = self._rsa_enc_cycle(key_tuple, pub_key)
            return aes_key_dictionary
        else:
            clients = list(key_dict.keys())
            for client in clients:
                pub_key = key_dict[client]
                aes_key_dictionary[client] = self._rsa_enc_cycle(key_tuple, pub_key)
            return aes_key_dictionary

    @staticmethod
    def _rsa_enc_cycle(plain_tuple, public_key):
        """ Encrypts all items in a tuple via RSA method """

        rsa = RSA.Encryptor()
        cipher_list = list()
        for i in range(0, len(plain_tuple)):
            cipher_list[i] = rsa.encrypt(plain_tuple[i], public_key, 'b')
        return tuple(cipher_list)

    def _rsa_dec_cycle(self, cipher_tuple):
        """ Decrypts all items in a tuple via RSA method """

        rsa = RSA.Decryptor()
        plain_list = list()
        for i in range(0, len(cipher_tuple)):
            plain_list[i] = rsa.decrypt(
                cipher_tuple[i], self.priv_key, self.priv_key_password, 'b')
        return tuple(plain_list)

    def _validation(self, data, mode):
        """A function to check message's signature and validate it to confirm its's authenticity with sender"""

        sign = RSA.Signature()
        if self.username in data:
            verifier = data[self.username]
            signature_state = sign.verify(self.sign, self.pub_key, verifier, 'b')
            self.enc_state = self.username
        else:
            client_name = list(data)[0]
            verifier = data[client_name]
            self.enc_state = client_name
            if mode is 'p2g':
                pub_key = self.receiver_pub_key[client_name]
                signature_state = sign.verify(self.sign, pub_key, verifier, 'b')
            else:
                pub_key = self.receiver_pub_key
                signature_state = sign.verify(self.sign, pub_key, verifier, 'b')
        return signature_state

    def _key_derivation(self, data, mode):
        if (self.enc_state is self.username) or (mode is 'p2g'):
            correct_key = data[self.username]
        else:
            correct_key = data['client']
        self.enc_state = None
        credentials = self._rsa_dec_cycle(correct_key)
        return credentials

    @staticmethod
    def _aes_message_dec(data, confidential):
        aes = AES.AES()
        data = aes.dec(data, confidential[1], confidential[2], confidential[0])
        if data is False:
            return data
        return data.decode('utf-8')


class Send(Cipher):
    """Send class for authenticated encryption"""

    def __init__(self, username=None, pub_key=None, priv_key=None, priv_key_password=None, receiver_pub_key=None):
        super(Send, self).__init__(self, username, pub_key, priv_key, priv_key_password, receiver_pub_key)
        self.aes = AES.AES()
        self.message = namedtuple('Message', 'signature keys cipher')
        self.s_message = namedtuple('Message to Server', 'keys cipher')
        if pub_key is not None:
            sign = RSA.Signature()
            self.signature = sign.sign(self.sign, self.priv_key, self.priv_key_password, 'b')

    def encrypt(self, data, mode):
        if mode is ('p2p' or 'p2g'):
            data = '@{}: {}'.format(self.username, data)
            signature = {self.username: self.signature}
        key = BasicFunctions.password_gen()
        credential = self.aes.enc(data, key)
        credentials = (credential.key, credential.nonce, credential.tag)
        if mode is 'p2g':
            dictionary = self._rsa_encrypt(credentials)
            return self.message(signature, dictionary, credential.cipher)
        elif mode is 'p2s':
            key_dict = self._rsa_enc_cycle(credentials, self.receiver_pub_key)
            return self.s_message(key_dict, credential.cipher)
        elif mode is 'p2p':
            key_dict = {self.username: self.pub_key, 'client': self.receiver_pub_key}
            key_dict = self._rsa_encrypt(credentials, key_dict)
            return self.message(signature, key_dict, credential.cipher)


class Receive(Cipher):
    """Receive class for authenticated decryption"""

    def decrypt(self, data, mode):
        """Wrapper for authenticating and then decrypting functions"""

        # At first we should make sure that the message is authenticated.
        if self._validation(data.signature, mode):
            # Decrypting
            credentials = self._key_derivation(data.keys, mode)
            data = self._aes_message_dec(data.cipher, credentials)
            # If message 'tag'(second layer of authenticity check) isn't correct
            # message is not authenticated
            if data is False:
                raise MessageTagDoesNotMatch
            else:
                # Returning decrypted message.
                return data
        # If the signature isn't same as we expected to be
        # message is not authenticated
        else:
            raise MessageSignatureDoesNotMatch


class MessageSignatureDoesNotMatch(Exception):
    pass


class MessageTagDoesNotMatch(Exception):
    pass
