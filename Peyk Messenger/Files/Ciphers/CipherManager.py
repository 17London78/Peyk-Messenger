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
import random
from Files.Ciphers import RSA, AES


class Cipher:
    def __init__(self, data, username, client_name, pubKeyPath, c_pubkeypath,
                 privKeyPath, privKeyPassword):
        self.dataTuple = data
        self.data = data
        self.username = username
        self.pubKeyPath = pubKeyPath
        self.privKeyPath = privKeyPath
        self.privKeyPassword = privKeyPassword
        self.client_name = client_name
        self.c_pubkeypath = c_pubkeypath


class sendEnc(Cipher):

    def _lettergen(self):
        letters = '!$%&0123456789<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZmnopqrstuvwxyz'
        letters = list(letters)
        random.shuffle(letters)
        letters = ''.join(letters)
        return letters

    def _RSAencryptCycle(self, Tuple, publicKey):
        rsa = RSA.Encryptor()
        Tuple = list(Tuple)
        for i in range(0, len(Tuple)):
            Tuple[i] = rsa.encrypt(Tuple[i], publicKey)
        return tuple(Tuple)

    def sendEnc(self):
        data = '@{}: {}'.format(self.username, self.data)
        data = data.encode('utf-8')
        sign = RSA.Signature()
        signature = sign.sign('LSAssp', self.privKeyPath, self.privKeyPassword)
        aes = AES.aes()
        key = self._lettergen()
        aesTuple = aes.enc(data, key)
        confidential = (aesTuple[1], aesTuple[2], aesTuple[3])
        Csend = self._RSAencryptCycle(confidential, self.c_pubkeypath)
        Usend = self._RSAencryptCycle(confidential, self.pubKeyPath)
        Message = ({self.username: signature}, {self.client_name: Csend,
                   self.username: Usend}, aesTuple[0])
        return Message


class recDec(Cipher):
    def decrypt(self):
        if self._validation():
            data = self._aesMessageDec()
            return data
        else:
            raise MessageSignatureDoesNotMatch

    def _validation(self):
        return self._valid_step_two(self._valid_step_one())

    def _valid_step_one(self):
        try:
            verifier = self.dataTuple[0][self.client_name]
            idNum = 1
        except KeyError:
            verifier = self.dataTuple[0][self.username]
            idNum = 2
        return (verifier, idNum)

    def _valid_step_two(self, verifier):
        sign = RSA.Signature()
        if verifier[1] == 1:
            signatureState = sign.verify('LSAssp', self.c_pubkeypath,
                                         verifier[0])
        else:
            signatureState = sign.verify('LSAssp', self.pubKeyPath,
                                         verifier[0])
        return signatureState

    def _aesMessageDec(self):
        aes = AES.aes()
        confidential = self._keyDerivator(self.dataTuple[1])
        data = aes.dec(self.dataTuple[2], confidential[1], confidential[2],
                       confidential[0])
        if data is False:
            raise MessageTagDoesNotMatch
        return data.decode('utf-8')

    def _keyDerivator(self, confidentialDict):
        CorrectSent = confidentialDict[self.username]
        confidential = self._RSAdecryptCycle(CorrectSent)
        return confidential

    def _RSAdecryptCycle(self, Tuple):
        rsa = RSA.Decryptor()
        Tuple = list(Tuple)
        for i in range(0, len(Tuple)):
            Tuple[i] = rsa.decrypt(Tuple[i], self.privKeyPath,
                                   self.privKeyPassword)
        return tuple(Tuple)


class MessageSignatureDoesNotMatch(Exception):
    pass


class MessageTagDoesNotMatch(Exception):
    pass
