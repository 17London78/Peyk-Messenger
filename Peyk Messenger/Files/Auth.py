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
import pickle
from Files.Ciphers import RSA
from Crypto.Hash import SHA3_512
from Files.Assests import BasicFunctions


class Authenticator:
    def __init__(self, path1, path2):
        self.users, self.clients = self._load_database(path1, path2)
        self.path = path1, path2

    def _UA(self, path):
        with open(path, 'rb') as handle:
            users = pickle.loads(handle.read())
        return users

    def _CA(self, path):
        with open(path, 'rb') as handle:
            clients = pickle.loads(handle.read())
        return clients

    def _user_init(self, path):
        users = self._UA(path)
        for username in users:
            user = users[username]
            user.is_logged_in = False
        return users

    def _load_database(self, path1, path2):
        U = os.path.isfile(path1)
        C = os.path.isfile(path2)
        if U or C:
            if U and (C is False):
                users = self._user_init(path1)
                clients = {}
            elif (U is False) and C:
                users = {}
                clients = self._CA(path2)
            elif U and C:
                users = self._user_init(path1)
                clients = self._CA(path2)
        else:
            users = {}
            clients = {}
        return users, clients

    def _save_U_to_database(self):
        path = self.path[0]
        with open(path, 'wb+') as handle:
            pickle.dump(self.users, handle, pickle.HIGHEST_PROTOCOL)

    def _save_C_to_database(self):
        path = self.path[1]
        with open(path, 'wb+') as handle:
            pickle.dump(self.clients, handle, pickle.HIGHEST_PROTOCOL)

    def add_user(self, username, password, path):
        if username in self.users:
            raise UsernameAlreadyExists(username)
        if len(password) < 6:
            raise PasswordTooShort(username)
        userobject = User(username, password, path)
        self.users[username] = userobject
        self._save_U_to_database()

    def add_client(self,
                   username,
                   databasePath,
                   ip=None,
                   port=None,
                   pubKeyPath=None,
                   password=None):

        if username in self.clients:
            raise UsernameAlreadyExists(username)
        clientobject = Client(username, databasePath, ip, port, pubKeyPath,
                              password)
        self.clients[username] = clientobject
        self._save_C_to_database()

    def changePassword(self, username, new_password, mode, old_password=None):
        if mode == 'user':
            if username in self.users:
                user = self.users[username]
                user._changePassword(old_password, new_password)
                self._save_U_to_database()
            else:
                raise UsernameDoesNotExists(username)
        elif mode == 'client':
            if username in self.clients:
                Client = self.clients[username]
                Client._changePassword(new_password)
                self._save_C_to_database()
            else:
                raise ClientDoesNotExist(username)

    def changeClient(self, username, databasePath, ip=None, port=None,
                     pubKey=None, password=None):
        if username in self.clients:
            Client = self.clients[username]
            if ip is not None:
                Client._changeIp(ip)
            if port is not None:
                Client._changePort(port)
            if password is not None:
                self.changePassword(username, password, 'client')
            if pubKey is not None:
                Client.pubKeyPath = Client._publicKey(pubKey, databasePath)
            self._save_C_to_database()
        else:
            raise ClientDoesNotExist(username)

    def deleteClient(self, username):
        if username in self.clients:
            del self.clients[username]
            self._save_C_to_database()
        else:
            raise ClientDoesNotExist(username)

    def login(self, username, password):
        try:
            user = self.users[username]
        except KeyError:
            raise InvalidUsername(username)

        if not user._check_password(password):
            raise InvalidPassword(username, user)

        user.is_logged_in = True
        return True

    def is_logged_in(self, username):
        if username in self.users:
            return self.users[username].is_logged_in
        return False


class User:
    def __init__(self, username, password, path):
        self.username = username
        self.password = self._encrypt_pw(password)
        self.privpath, self.pubpath = self._generatRSA(username, self.password, path)
        self.is_logged_in = False

    def _encrypt_pw(self, password):
        hash_string = (self.username + password)
        hash_string = hash_string.encode('utf8')
        return SHA3_512.new(hash_string).hexdigest()

    def _check_password(self, password):
        encrypted = self._encrypt_pw(password)
        return encrypted == self.password

    def _changePassword(self, old_password, new_password):
        if self.is_logged_in is True:
            if self._check_password(old_password) is True:
                self.password = self._encrypt_pw(new_password)
            else:
                raise InvalidPassword(self.username)
        else:
            raise NotLoggedInError(self.username)

    def _generatRSA(self, username, password, path):
        rsa = RSA.rsa()
        privpath = os.path.join(path, '{}_private.pem'.format(username))
        pubpath = os.path.join(path, '{}_public.pem'.format(username))
        rsa.export(privpath, pubpath, password)
        return privpath, pubpath


class Client:
    def __init__(self,
                 username,
                 databasePath,
                 ip=None,
                 port=None,
                 pubKeyPath=None,
                 password=None):
        self.username = username
        self.connect = [ip, port]
        self.password = password
        if pubKeyPath is not None:
            self.pubKeyPath = self._publicKey(pubKeyPath, databasePath)
        if self.password is not None:
            self.password = self._encrypt_pw(password)

    def _publicKey(self, path, databasePath):
        if os.path.exists(path):
            key = BasicFunctions.binaryReader(path)
        else:
            raise PathDoesNotExist(self.username)
        importpath = os.path.join(databasePath, '{}.pem'.format(self.username))
        BasicFunctions.binaryWriter(importpath, key)
        return importpath

    def _changeIp(self, ip):
        self.connect[0] = ip

    def _changePort(self, port):
        self.connect[1] = port

    def _encrypt_pw(self, password):
        hash_string = (password)
        hash_string = hash_string.encode('utf8')
        return SHA3_512.new(hash_string).hexdigest()

    def _changePassword(self, new_password):
        self.password = self._encrypt_pw(new_password)


class AuthException(Exception):
    def __init__(self, username, user=None):
        super().__init__(username, user)
        self.username = username
        self.user = user


class UsernameDoesNotExists(AuthException):
    pass


class UsernameAlreadyExists(AuthException):
    pass


class UserAlreadySignedIn(AuthException):
    pass


class ClientDoesNotExist(AuthException):
    pass


class ClientAlreadyHasPublicKey(AuthException):
    pass


class PasswordTooShort(AuthException):
    pass


class InvalidUsername(AuthException):
    pass


class InvalidPassword(AuthException):
    pass


class NotLoggedInError(AuthException):
    pass


class PathDoesNotExist(AuthException):
    pass


class NotPermittedError(AuthException):
    pass


class PermissionError(Exception):
    pass
