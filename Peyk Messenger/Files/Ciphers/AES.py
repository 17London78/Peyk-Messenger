#!/usr/bin/python3
"""
  Peyk Secure Encrypted Messenger
  GNU AGPL 3.0 Licensed
  Copyright (C) 2018 17London78 Inc. (17London78 at protonmail.com)
  =========================================
  Islamic Republic of Iran Broadcasting University (IRIBU)
  Faculty of Telecommunication Engineering
  Author: Mohammad Mahdi Baghbani Pourvahid
  Major: Telecommunication Engineering
  <MahdiBaghbani@protonmail.com>
  https://www.mahdibaghbanii.wordpress.com
  https://www.github.com/MahdiBaghbani
  Company: 17London78 Inc.
  https://www.17London78.ir
  https://www.github.com/17London78
  =========================================

"""
from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256


class aes:
    def enc(self, data, key):
        self._encrypt(data, key)
        return (self.cipherdata, key.encode('utf_8'), self.nonce,
                self.tag)

    def dec(self, data, nonce, tag, key):
        self._decrypt(data, nonce, tag, key)
        return self.plaindata

    def _encrypt(self, data, key):
        key = self._keygen(key)
        cipher = AES.new(key, AES.MODE_EAX)
        self.nonce = cipher.nonce
        self.cipherdata, self.tag = cipher.encrypt_and_digest(data)

    def _decrypt(self, data, nonce, tag, key):
        key = self._keygen(key)
        decipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaindata = decipher.decrypt(data)
        try:
            decipher.verify(tag)
        except ValueError:
            self.plaindata = False
        self.plaindata = plaindata

    def _keygen(self, key):
        if type(key) is str:
            key = key.encode('utf-8')
        key_256bit = SHA3_256.new()
        key_256bit.update(key)
        key = key_256bit.digest()
        return key
