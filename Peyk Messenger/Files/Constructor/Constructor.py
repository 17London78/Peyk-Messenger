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
from Files.Assets import BasicFunctions


class Construct:
    def __init__(self, ip, port, username, pubKeyPath, privKeyPath, privKeyPassword, c_pubkeypath, password=None):
        self.port = port
        self.ip = ip
        self.password = password
        self.username = username
        self.pubKeyPath = pubKeyPath
        self.privKeyPath = privKeyPath
        self.privKeyPassword = privKeyPassword
        self.c_pubkeypath = c_pubkeypath
        self.folderPath = os.path.dirname(os.path.abspath(__file__))
        self.createPath = self._pathFinder()
        self._run()

    def _run(self):
        self._init_GUI()

    def _pathFinder(self):
        Folder, head = BasicFunctions.headTail(self.folderPath)
        return head

    def _init_GUI(self):
        template = BasicFunctions.reader(os.path.join(self.folderPath, 'GUI.py'))
        GUI = template.format(self.port, self.ip, self.password, self.username,
                              self.pubKeyPath, self.privKeyPath,
                              self.privKeyPassword, self.c_pubkeypath)
        path = os.path.join(self.createPath, 'GUI.py')
        BasicFunctions.writer(path, GUI)
