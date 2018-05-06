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
from Files.Server import ServerUtil


class Server:
    def __init__(self, path):
        self.path = path
        self.server = ServerUtil.ServerUtil(path)

    def add_server(self, name, ip, port, client, password=None):
        self.server.add_server(name, ip, port, client, password)

    def edit_server(self, name, new_name=None, new_ip=None, new_port=None, new_password=None):
        self.server.server_editor(name, new_name, new_ip, new_port, new_password)


def server_init(path, file):
    path = os.path.join(path, file)
    return Server(path)
