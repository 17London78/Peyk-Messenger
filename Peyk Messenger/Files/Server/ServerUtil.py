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


class ServerUtil:
    def __init__(self, path):
        self.path = path
        self.servers = self._load_database()

    def _load_database(self):
        servers = {}
        if os.path.isfile(self.path):
            servers = BasicFunctions.reader(self.path, 'p')
        return servers

    def _save_s_to_database(self):
        BasicFunctions.writer(self.path, self.servers, 'p')

    def add_server(self, name, ip, port, client, password):
        if name in self.servers:
            raise UsernameAlreadyExists(name)
        server_object = Server(name, ip, port, client, password)
        self.servers[name] = server_object
        self._save_s_to_database()

    def access_server(self, name):
        if name in self.servers:
            server_object = self.servers[name]
            return server_object
        else:
            raise UsernameDoesNotExists(name)

    def server_editor(self, name, new_name, new_ip, new_port, new_password):
        if name in self.servers:
            server_object = self.servers[name]
            if new_password is not None:
                server_object.change_password(new_password)
            if new_ip is not None:
                server_object.change_ip(new_ip)
            if new_port is not None:
                server_object.change_port(new_port)
            if new_name is not None:
                if new_name in self.servers:
                    raise UsernameAlreadyExists(new_name)
                else:
                    server_object.change_name(new_name)
                    self.servers[new_name] = server_object
                    del self.servers[name]
            self._save_s_to_database()
        else:
            raise UsernameDoesNotExists(name)

    def add_key(self, name, key_one, key_two):
        if name in self.servers:
            server_object = self.servers[name]
            server_object.add_key(key_one, key_two)
            self._save_s_to_database()
        else:
            raise UsernameDoesNotExists(name)

    def update(self, name, username):
        if name in self.servers:
            server_object = self.servers[name]
            server_object.status[username] = 1
            self._save_s_to_database()
        else:
            raise UsernameDoesNotExists(name)

    def query(self, name, username):
        if name in self.servers:
            server_object = self.servers[name]
            try:
                status = server_object.status[username]
                return status
            except KeyError:
                return 0
        else:
            raise UsernameDoesNotExists(name)

    def delete_server(self, name):
        if name in self.servers:
            del self.servers[name]
            self._save_s_to_database()
        else:
            raise UsernameDoesNotExists(name)


class Server:
    def __init__(self, name, ip, port, client, password):
        self.name = name
        self.connect = [ip, port]
        self.client = client
        if password is None:
            self.password = None
            self.tag = 'public server'
        else:
            self.password = BasicFunctions.hash_password(password)
            self.tag = 'private server'
        self.keys = [None, None]
        self.status = dict()

    def add_key(self, key_one, key_two):
        if key_one is not None:
            self.keys[0] = key_one
        if key_two is not None:
            self.keys[1] = key_two

    def change_name(self, name):
        self.name = name

    def change_ip(self, ip):
        if ip is not None:
            self.connect[0] = ip

    def change_port(self, port):
        if port is not None:
            self.connect[1] = port

    def check_password(self, password):
        encrypted = BasicFunctions.hash_password(password)
        return encrypted == self.password

    def change_password(self, new_password):
        if new_password is not None:
            self.password = BasicFunctions.hash_password(new_password)
            if self.tag is 'public server':
                self.tag = 'private server'


class UsernameDoesNotExists(Exception):
    pass


class UsernameAlreadyExists(Exception):
    pass
