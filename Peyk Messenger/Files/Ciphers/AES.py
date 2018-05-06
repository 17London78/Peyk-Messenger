#!/usr/bin/python3
"""
Peyk Secure Encrypted Messenger
GNU AGPL 3.0 Licensed
Copyright (C) 2018 17London78 Inc.
=========================================
A module for AES encrypt/decrypt using Crypto library
=========================================
"""
__author__ = "Mohammad Mahdi Baghbani Pourvahid"
__copyright__ = "Copyright (C) 2018 17London78 Inc."
__credits__ = ["Jadi mirmirani, Xysun, Al Sweigart"]
__license__ = "AGPL 3.0"
__maintainer__ = "Mohammad Mahdi Baghbani Pourvahid"
__email__ = "MahdiBaghbani@Protonmail.com"
__version__ = "0.01-alpha"
__status__ = "Development"

from Crypto.Cipher import AES as _AES
from Crypto.Hash import SHA3_256


class AES:
    """ Encrypt/decrypt via AES-EAX-256bit_key method """

    def enc(self, data, key, mode='d'):
        key_256bit = self._keygen(key)
        cipher = _AES.new(key_256bit, _AES.MODE_EAX)
        cipher_nonce = cipher.nonce
        cipher_data, cipher_tag = cipher.encrypt_and_digest(data)
        if mode is 'd':
            return cipher_data, key_256bit.encode('utf_8'), cipher_nonce, cipher_tag
        if mode is 'r':
            return cipher_nonce, cipher_tag, cipher_data

    def dec(self, data, nonce, tag, key):
        key = self._keygen(key)
        decipher = _AES.new(key, _AES.MODE_EAX, nonce=nonce)
        plain_data = decipher.decrypt(data)
        try:
            decipher.verify(tag)
        except ValueError:
            plain_data = False
        return plain_data

    @staticmethod
    def _keygen(key):
        if type(key) is str:
            key = key.encode('utf-8')
        key_256bit = SHA3_256.new()
        key_256bit.update(key)
        key = key_256bit.digest()
        return key
