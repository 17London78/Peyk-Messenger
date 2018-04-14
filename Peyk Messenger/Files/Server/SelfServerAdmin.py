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
import threading
from Files.Server import ServerScript
from Files.Constructor import Constructor


class SSA:
    def __init__(
            self,
            server_data,
            buffer_size,
            username,
            pubKeyPath,
            privKeyPath,
            privKeyPassword,
            c_pubkeypath,
    ):
        self.username = username
        self.pubKeyPath = pubKeyPath
        self.privKeyPath = privKeyPath
        self.privKeyPassword = privKeyPassword
        self.server_data = server_data
        self.c_pubkeypath = c_pubkeypath
        self.connect = self.server_data[0]
        self.password = None
        self.buffer_size = buffer_size
        if len(self.server_data) == 3:
            self.password = self.server_data[2]
        self.server = self._server_init()

    def _server_init(self):
        return ServerScript.server(self.connect[0], self.connect[1],
                                   self.buffer_size, self.username,
                                   self.password)

    def _start_server(self):
        try:
            threading.Thread(target=self.server.startServer).start()
            self._construct()
        except ServerScript.ServerFatalError:
            raise ServerAbort

    def _construct(self):
        Constructor.construct(self.connect[0], self.connect[1], self.username,
                              self.pubKeyPath, self.privKeyPath,
                              self.privKeyPassword, self.c_pubkeypath,
                              self.password)


class ServerAbort(Exception):
    pass
