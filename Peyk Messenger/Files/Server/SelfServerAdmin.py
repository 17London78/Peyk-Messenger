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

import threading
from Files.Server import ServerScript
from Files.Constructor import Constructor


class ServerAdmin:
    def __init__(self, connect, buffer_size, username, pubKeyPath, privKeyPath, privKeyPassword, c_pubkeypath, password=None):
        self.username = username
        self.pubKeyPath = pubKeyPath
        self.privKeyPath = privKeyPath
        self.privKeyPassword = privKeyPassword
        self.c_pubkeypath = c_pubkeypath
        self.server = ServerScript.server(connect[0], connect[1], buffer_size, username, password)

    def _construct(self):
        Constructor.construct(self.connect[0], self.connect[1], self.username,
                              self.pubKeyPath, self.privKeyPath,
                              self.privKeyPassword, self.c_pubkeypath,
                              self.password)


class ServerAbort(Exception):
    pass
