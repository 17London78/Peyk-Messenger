#!/usr/bin/python3
"""
Peyk Secure Encrypted Messenger
GNU AGPL 3.0 Licensed
Copyright (C) 2018 17London78 Inc.
=========================================
A module for reading and writing to files
with wrapping python methods.
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

from .Auth import Authenticator


class CAS:
    def __init__(self, user_data_path, client_data_path, user_key_path):
        self.path = user_data_path, client_data_path, user_key_path
        self.cas = Authenticator(self.path[0], self.path[1])

    def signup(self, username, password):
        self.cas.add_user(username, password, self.path[2])

    def login(self, username, password):
        return self.cas.login(username, password)

    def sign_out(self, username):
        if self.cas.is_logged_in(username):
            self.cas.users[username].is_logged_in = False

    def change_password(self, username, old_password, new_password):
        self.cas.change_password(username, old_password, new_password)

    def add_client(self, username, ip, port, pub_key_path):
        self.cas.add_client(username, ip, port, pub_key_path)

    def edit_client(self, username, name=None, ip=None, port=None, pub_key_path=None):
        self.cas.edit_client(username, name, ip, port, pub_key_path)

    def delete_client(self, username):
        self.cas.delete_client(username)
