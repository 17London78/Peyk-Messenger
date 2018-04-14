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
from Files.Assests import BasicFunctions


class construct:
    def __init__(self,
                 ip,
                 port,
                 username,
                 pubKeyPath,
                 privKeyPath,
                 privKeyPassword,
                 c_pubkeypath,
                 password=None):
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
