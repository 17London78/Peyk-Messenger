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
from Files.Server import ServerUtil
from Files.Assests import BasicFunctions

MAIN_PATH = os.path.dirname(os.path.abspath(__file__))
File, head = BasicFunctions.headTail(MAIN_PATH)
DATA_PATH = os.path.join(head, 'Data')
USER_DB_PATH = os.path.join(DATA_PATH, 'User Database')
SM_DATA_PATH = os.path.join(USER_DB_PATH, 'serverMDB.txt')
SU_DATA_PATH = os.path.join(USER_DB_PATH, 'serverUDB.txt')


class SManager:
    def __init__(self, path):
        self.path = path
        self.serverU = self._SERVERU_init(self.path)

    def _SERVERU_init(self, path):
        server = ServerUtil.ServerUtil(path)
        return server

    def addServer(self, name, ip, port, password):
        self.serverU.add_server(name, ip, port, password)

    def changeSname(self, old_name, new_name):
        self.serverU.change_S_name(old_name, new_name)

    def changeSconnect(self, name, new_ip=None, new_port=None):
        self.serverU.change_S_connect(name, new_ip, new_port)

    def changeSpassword(self, name, password):
        self.serverU.change_S_password(name, password)


class Server1st:
    def __init__(self, path=SM_DATA_PATH):
        self.server = SManager(path)


class Server2nd:
    def __init__(self, path=SU_DATA_PATH):
        self.server = SManager(path)
