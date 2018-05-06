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

from Crypto.Random import random
from Files.Ciphers import RSA, AES


class Cipher:
    """A base class for authenticated encryption and decryption"""

    def __init__(self, data=None, username=None, pub_key=None, priv_key=None, priv_key_password=None, recipient_pubkey=None):
        if type(data) == tuple:
            self.dataTuple = data
        elif type(data) == str:
            self.data = data
        self.username = username
        self.pubKey = pub_key
        self.privKey = priv_key
        self.privKeyPassword = priv_key_password
        self.r_pubkey = recipient_pubkey
        self.sign = 'LSAssp'
        self.enc_state = None

    @staticmethod
    def _lettergen():
        """A random password generator for AES encrypting"""

        letters = '!$%&0123456789<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZmnopqrstuvwxyz'
        letters = list(letters)
        # Using Crypto.Random library for cryptographic random function
        random.shuffle(letters)
        letters = ''.join(letters)
        return letters

    def _rsa_encrypt(self, key_tuple, key_dict=None):
        aes_key_dictionary = dict()
        if key_dict is None:
            clients = list(self.r_pubkey.keys())
            for client in clients:
                pub_key = self.r_pubkey[client]
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
                cipher_tuple[i], self.privKey, self.privKeyPassword, 'b')
        return tuple(plain_list)

    def _validation(self, mode):
        """A function to check message's signature and validate it to confirm
        its's authenticity with sender"""

        sign = RSA.Signature()
        if self.username in self.dataTuple[0]:
            verifier = self.dataTuple[0][self.username]
            signature_state = sign.verify(self.sign, self.pubKey, verifier, 'b')
            self.enc_state = self.username
        else:
            client_name = list(self.dataTuple[0])[0]
            verifier = self.dataTuple[0][client_name]
            self.enc_state = client_name
            if mode is 'p2g':
                pub_key = self.r_pubkey[client_name]
                signature_state = sign.verify(self.sign, pub_key, verifier, 'b')
            else:
                pub_key = self.r_pubkey
                signature_state = sign.verify(self.sign, pub_key, verifier, 'b')
        return signature_state

    def _key_derivator(self, mode):
        if (self.enc_state == self.username) or (mode == 'p2g'):
            correct_key = self.dataTuple[1][self.username]
        else:
            correct_key = self.dataTuple[1]['client']

        confidential = self._rsa_dec_cycle(correct_key)
        return confidential

    def _aes_message_dec(self, confidential):
        aes = AES.aes()
        data = aes.dec(self.dataTuple[2], confidential[1], confidential[2], confidential[0])
        if data is False:
            return data
        return data.decode('utf-8')


class Send(Cipher):
    """Send class for authenticated encryption"""

    def encrypt(self, mode):
        if mode is ('p2p' or 'p2g'):
            data = '@{}: {}'.format(self.username, self.data)
            data = data.encode('utf-8')
            sign = RSA.Signature()
            signature = sign.sign(self.sign, self.privKey, self.privKeyPassword, 'b')
            signature = {self.username: signature}
        elif mode is 'p2s':
            data = self. data.encode('utf-8')
        else:
            raise ModeIsNotValid
        aes = AES.aes()
        key = self._lettergen()
        aes_tuple = aes.enc(data, key)
        confidential = (aes_tuple[1], aes_tuple[2], aes_tuple[3])
        if mode is 'p2g':
            dictionary = self._rsa_encrypt(confidential)
            message = (signature, dictionary, aes_tuple[0])
            return message
        elif mode is 'p2s':
            key_dict = self._rsa_enc_cycle(confidential, self.r_pubkey)
            message = (key_dict, aes_tuple[0])
            return message
        elif mode is 'p2p':
            key_dict = {self.username: self.pubKey, 'client': self.r_pubkey}
            key_dict = self._rsa_encrypt(confidential, key_dict)
            message = (signature, key_dict, aes_tuple[0])
            return message


class Receive(Cipher):
    """Receive class for authenticated decryption"""

    def decrypt(self, mode):
        """Wrapper for authenticating and then decrypting functions"""

        # At first we should make sure that the message is authenticated.
        if self._validation(mode):
            # Decrypting
            confidential = self._key_derivator(mode)
            data = self._aes_message_dec(confidential)
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


class ModeIsNotValid(Exception):
    pass
