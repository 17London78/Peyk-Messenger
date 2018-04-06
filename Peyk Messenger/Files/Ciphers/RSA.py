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
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA3_512
from Files.Assests import BasicFunctions


class rsa:
    def __init__(self):
        self.private, self.public = self._generator()

    def _generator(self):
        privateSet = RSA.generate(2048)
        publicKey = privateSet.publickey()
        return privateSet, publicKey

    def export(self, privpath, pubpath, password=0000):

        priv = self.private.exportKey('PEM', password)
        pub = self.public.exportKey('PEM')

        privpath = privpath
        pubpath = pubpath

        BasicFunctions.binaryWriter(privpath, priv)
        BasicFunctions.binaryWriter(pubpath, pub)


class Encryptor:
    def encrypt(self, message, pubKeyPath):
        key = RSA.importKey(BasicFunctions.binaryReader(pubKeyPath))
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(message)
        return ciphertext


class Decryptor:
    def decrypt(self, message, privKeyPath, password):
        key = RSA.importKey(BasicFunctions.binaryReader(privKeyPath), password)
        cipher = PKCS1_OAEP.new(key)
        plaintext = cipher.decrypt(message)
        return plaintext


class Signature:
    def __init__(self):
        pass

    def sign(self, message, privKeyPath, password):
        if type(message) is str:
            message = message.encode('utf-8')
        key = RSA.importKey(BasicFunctions.binaryReader(privKeyPath), password)
        Hash = SHA3_512.new(message)
        signature = pss.new(key).sign(Hash)
        return signature

    def verify(self, message, pubKeyPath, signature):
        if type(message) is str:
            message = message.encode('utf-8')
        key = RSA.importKey(BasicFunctions.binaryReader(pubKeyPath))
        Hash = SHA3_512.new(message)
        verifier = pss.new(key)
        try:
            verifier.verify(Hash, signature)
        except (ValueError, TypeError):
            return False
        return True
