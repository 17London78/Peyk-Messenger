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

import os
from ..Assets import BasicFunctions


class Authenticator:
    def __init__(self, user_database_path, client_database_path):
        first_path = os.path.join(user_database_path, 'userDB.txt')
        second_path = os.path.join(client_database_path, 'clientsDB.txt')
        self.path = first_path, second_path
        self.users, self.clients = self._load_database()

    def _load_database(self):
        users = {}
        clients = {}
        if os.path.isfile(self.path[0]):
            users = self._user_load()
        if os.path.isfile(self.path[1]):
            clients = BasicFunctions.reader(self.path[1], 'p')
        return users, clients

    def _user_load(self):
        users = BasicFunctions.reader(self.path[0], 'p')
        for username in users:
            user = users[username]
            user.is_logged_in = False
        return users

    def _save_u_to_database(self):
        BasicFunctions.writer(self.path[0], self.users, 'p')

    def _save_c_to_database(self):
        BasicFunctions.writer(self.path[1], self.clients, 'p')

    def add_user(self, username, password, path):
        if username in self.users:
            raise UsernameAlreadyExists(username)
        if len(password) < 6:
            raise PasswordTooShort(username)
        user_object = User(username, password, path)
        self.users[username] = user_object
        self._save_u_to_database()

    def change_password(self, username, old_password, new_password):
        if username in self.users:
            user = self.users[username]
            user.change_password(old_password, new_password)
            self._save_u_to_database()
        else:
            raise UsernameDoesNotExists(username)

    def login(self, username, password):
        try:
            user = self.users[username]
        except KeyError:
            return False
        if user.is_logged_in is False:
            if not user.check_password(password):
                return False
            user.is_logged_in = True
            return True
        else:
            return False

    def is_logged_in(self, username):
        if username in self.users:
            return self.users[username].is_logged_in
        return False

    def add_client(self, client_name, ip, port, pub_key_path):
        if client_name in self.clients:
            raise UsernameAlreadyExists(client_name)
        client_object = Client(client_name, ip, port, pub_key_path)
        self.clients[client_name] = client_object
        self._save_c_to_database()

    def edit_client(self, client_name, new_name, ip, port, pub_key_path):
        if client_name in self.clients:
            client = self.clients[client_name]
            if ip is not None:
                client.change_ip(ip)
            if port is not None:
                client.change_port(port)
            if pub_key_path is not None:
                client.public_key = client.public_key(pub_key_path)
            if new_name is not None:
                if new_name in self.clients:
                    raise UsernameAlreadyExists(new_name)
                else:
                    client.change_name(new_name)
                    self.clients[new_name] = client
                    del self.clients[client_name]
            self._save_c_to_database()
        else:
            raise ClientDoesNotExist(client_name)

    def delete_client(self, client_name):
        if client_name in self.clients:
            del self.clients[client_name]
            self._save_c_to_database()
        else:
            raise ClientDoesNotExist(client_name)


class User:
    def __init__(self, username, password, path):
        self.username = username
        self.password = BasicFunctions.hash_password(password, self.username)
        self. pub_key, self.priv_key, self.pub_path, self.priv_path = BasicFunctions.rsa_gen(username, 4096, self.password, path)
        self.is_logged_in = False

    def check_password(self, password):
        encrypted = BasicFunctions.hash_password(password, self.username)
        return encrypted == self.password

    def change_password(self, old_password, new_password):
        if self.is_logged_in is True:
            if self.check_password(old_password) is True:
                self.password = BasicFunctions.hash_password(new_password, self.username)
            else:
                raise InvalidPassword(self.username)
        else:
            raise NotLoggedInError(self.username)


class Client:
    def __init__(self, client_name, ip, port, pub_key_path):
        self.client_name = client_name
        self.connect = [ip, port]
        if pub_key_path is not None:
            self.public_key = self._public_key(pub_key_path)
        elif pub_key_path is None:
            self.public_key = None

    def _public_key(self, path, mode=None):
        if os.path.exists(path):
            key = BasicFunctions.reader(path, 'b')
            if mode is 'e':
                os.remove(path)
            return key
        else:
            raise PathDoesNotExist(self.client_name)

    def change_name(self, name):
        self.client_name = name

    def change_ip(self, ip):
        self.connect[0] = ip

    def change_port(self, port):
        self.connect[1] = port


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
