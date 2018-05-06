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

import glob
from Files.Assets import BasicFunctions
from Files.Ciphers import AES


def file_crypt(info, path, password, mode):
    def path_finder(i, p, m):
        if m is 'e':
            t = 'txt'
        elif m is 'd':
            t = 'aes'
        if i is 'Windows':
            p = '{}\\**\\*.{}'.format(p, t)
        elif i is 'Linux':
            p = '{}/**/*.{}'.format(p, t)
        return glob.glob(p, recursive=True)
    file_list = path_finder(info, path, mode)
    aes = AES.AES()
    if mode is 'e':
        for file in file_list:
            data = BasicFunctions.reader(file, 'b')
            encrypted_data = aes.enc(data, password, 'r')
            file = file.replace('txt', 'aes')
            BasicFunctions.writer(file, encrypted_data, 'c')
    elif mode is 'd':
        for file in file_list:
            data = BasicFunctions.reader(file, 'c')
            plain_data = aes.dec(data[2], data[0], data[1], password)
            file = file.replace('aes', 'txt')
            BasicFunctions.writer(file, plain_data, 'b')
