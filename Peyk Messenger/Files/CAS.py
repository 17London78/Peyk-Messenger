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
import os
from Files import Auth

MAIN_PATH = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(MAIN_PATH, 'Data')
USER_DB_PATH = os.path.join(DATA_PATH, 'User Database')
U_DATA_PATH = os.path.join(USER_DB_PATH, 'userDB.txt')
U_KEY_PATH = os.path.join(USER_DB_PATH, 'User Key Database')
C_DATA_PATH = os.path.join(USER_DB_PATH, 'clientDB.txt')
C_KEY_PATH = os.path.join(USER_DB_PATH, 'Client Public Keys')


class CAS:
    def __init__(self,
                 userdatapath=U_DATA_PATH,
                 clientdatapath=C_DATA_PATH,
                 userkeypath=U_KEY_PATH,
                 clientkeypath=C_KEY_PATH):
        self.path = [
            userdatapath,
            clientdatapath,
            userkeypath,
            clientkeypath,
        ]
        self.cas = self._CAS_init(self.path[0], self.path[1])

    def _CAS_init(self, path1, path2):
        cas = Auth.Authenticator(path1, path2)
        return cas

    def signUp(self, username, password):
        self.cas.add_user(username, password, self.path[2])

    def signIn(self, username, password):
        if self.cas.is_logged_in(username):
            raise Auth.UserAlreadySignedIn(username)

        verify = self.cas.login(username, password)
        return verify

    def signOut(self, username):
        if self.cas.is_logged_in(username):
            self.cas.users[username].is_logged_in = False
        else:
            raise Auth.InvalidUsername(username)

    def changePassword(self, username, old_password, new_password):
        self.cas.changePassword(username, old_password=old_password,
                                new_password=new_password, mode='user')

    def addClient(self, username, ip, port, pubKeyPath, password=None):
        self.cas.add_client(username, self.path[3], ip, port, pubKeyPath,
                            password)

    def editClient(self, username, ip=None, port=None, pubKey=None,
                   password=None):
        self.cas.changeClient(username, self.path[3], ip, port, pubKey,
                              password)

    def removeClient(self, username):
        self.cas.deleteClient(username)
