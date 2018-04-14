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
from Files import Auth
from Crypto.Hash import SHA3_512


class ServerUtil:
    def __init__(self, path):
        self.servers = self._load_database(path)
        self.path = path

    def _SA(self, path):
        with open(path, 'rb') as handle:
            servers = pickle.loads(handle.read())
        return servers

    def _load_database(self, path):
        S = os.path.isfile(path)
        if S:
            servers = self._SA(path)
        else:
            servers = {}
        return servers

    def _save_S_to_database(self):
        path = self.path
        with open(path, 'wb+') as handle:
            pickle.dump(self.servers, handle, pickle.HIGHEST_PROTOCOL)

    def add_server(self, name, ip, port, password=None, client=None):
        if name in self.servers:
            raise Auth.UsernameAlreadyExists(name)
        serverobject = Server(name, ip, port, password, client)
        self.servers[name] = serverobject
        self._save_S_to_database()

    def server_editor(self, name=None, new_name=None, new_ip=None,
                      new_port=None, new_password=None):
        if name in self.servers:
            serverobject = self.servers[name]
            if new_password is not None:
                serverobject._changePassword(new_password)
            if new_ip is not None:
                serverobject._changeIp(new_ip)
            if new_port is not None:
                serverobject._changePort(new_port)
            if new_name is not None:
                if new_name in self.servers:
                    raise Auth.UsernameAlreadyExists(new_name)
                else:
                    serverobject._changeName(new_name)
                    self.servers[new_name] = serverobject
                    del self.servers[name]
            self._save_S_to_database()
        else:
            raise Auth.UsernameDoesNotExists(name)

    def delete_server(self, name):
        if name in self.servers:
            del self.servers[name]
            self._save_S_to_database()


class Server:
    def __init__(self, name, ip, port, password=None, client=None):
        self.name = name
        self.connect = [ip, port]
        self.client = client
        if password is None:
            self.tag = 'public server'
        else:
            self.password = self._encrypt_pw(password)
            self.tag = 'private server'

    def _changeName(self, name):
        self.name = name

    def _changeIp(self, ip):
        if ip is not None:
            self.connect[0] = ip

    def _changePort(self, port):
        if port is not None:
            self.connect[1] = port

    def _check_password(self, password):
        encrypted = self._encrypt_pw(password)
        return encrypted == self.password

    def _encrypt_pw(self, password):
        hash_string = (password)
        hash_string = hash_string.encode('utf8')
        return SHA3_512.new(hash_string).hexdigest()

    def _changePassword(self, new_password):
        if new_password is not None:
            self.password = self._encrypt_pw(new_password)
            if self.tag == 'public server':
                self.tag = self.tag = 'private server'
