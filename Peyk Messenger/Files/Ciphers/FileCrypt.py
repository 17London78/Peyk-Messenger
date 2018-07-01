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
from ..Assets import BasicFunctions
from ..Ciphers import AES


def file_crypt(sys_info, path, password, mode):
    def path_finder(i, p, e):
        ext = e
        if i is 'Windows':
            files = '{}\\**\\*.{}'.format(p, ext)
        elif i is 'Linux':
            files = '{}/**/*.{}'.format(p, ext)
        return glob.glob(files, recursive=True)

    def encryptor(file_list, ext1, ext2):
        for file in file_list:
            data = BasicFunctions.reader(file, 'b')
            BasicFunctions.deleter(file)
            encrypted_data = aes.enc(data, password, 'r')
            file = file.replace(ext1, ext2)
            BasicFunctions.writer(file, encrypted_data, 'c')

    def decryptor(file_list, ext1, ext2):
        for file in file_list:
            data = BasicFunctions.reader(file, 'c')
            BasicFunctions.deleter(file)
            plain_data = aes.dec(data[2], data[0], data[1], password)
            file = file.replace(ext1, ext2)
            BasicFunctions.writer(file, plain_data, 'b')

    aes = AES.AES()
    if mode is 'e':
        txt_list = path_finder(sys_info, path, 'txt')
        pem_list = path_finder(sys_info, path, 'pem')
        encryptor(txt_list, 'txt', 'taes')
        encryptor(pem_list, 'pem', 'paes')

    elif mode is 'd':
        taes_list = path_finder(sys_info, path, 'taes')
        paes_list = path_finder(sys_info, path, 'paes')
        decryptor(taes_list, 'taes', 'txt')
        decryptor(paes_list, 'paes', 'pem')

