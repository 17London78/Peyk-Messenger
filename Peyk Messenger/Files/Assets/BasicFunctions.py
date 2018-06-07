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

import os
import socket
import pickle
from Crypto.Hash import SHA3_512
from Crypto.Random import random


def ip_finder():
    """ Finds local network ip of machine """

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.shutdown(socket.SHUT_RDWR)
    s.close()
    return ip


def password_gen():
    """A random password generator"""
    letters = '!$%&0123456789<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZmnopqrstuvwxyz'
    letters = list(letters)
    # Using Crypto.Random library for cryptographic random function
    random.shuffle(letters)
    letters = ''.join(letters)
    password = ''
    pass_length = random.randint(59, 236)
    for i in range(pass_length):
        password += random.choice(letters)
    return password


def hash_password(password, name=None):
    """ Hashes password for storing in database """

    if name is None:
        hash_string = password
    else:
        hash_string = (name + password)
    hash_string = hash_string.encode('utf8')
    return SHA3_512.new(hash_string).hexdigest()


def reader(path, mode):
    """ Wrapper for various reading from file methods """

    def text_reader(p):
        """ Reads in all of a textual file """

        with open(p, 'r') as read:
            data = read.read()
        return data

    def binary_reader(p):
        """ Reads in all of a file in binaries """

        with open(p, 'rb') as read:
            data = read.read()
        return data

    def pickle_reader(p):
        with open(p, 'rb') as read:
            data = pickle.loads(read.read())
        return data

    def crypt_reader(p):
        with open(p, 'rb') as read:
            data = [read.read(x) for x in (16, 16, -1)]
        return data

    if mode is 't':
        return text_reader(path)
    elif mode is 'b':
        return binary_reader(path)
    elif mode is 'p':
        return pickle_reader(path)
    elif mode is 'c':
        return crypt_reader(path)


def writer(path, data, mode):
    """ Wrapper for various writing to file methods """

    def text_writer(p, d):
        """ Writes out text to a file """

        with open(p, 'w+') as write:
            write.write(d)

    def binary_writer(p, d):
        """ Writes out binaries to a file """

        with open(p, 'wb') as write:
            write.write(d)

    def pickle_writer(p, d):
        """ Writes out a data serialized content in a file """

        with open(p, 'wb+') as write:
            pickle.dump(d, write, pickle.HIGHEST_PROTOCOL)

    def crypt_writer(p, d):
        with open(p, 'wb+') as write:
            [write.write(x) for x in d]

    if mode is 't':
        text_writer(path, data)
    elif mode is 'b':
        binary_writer(path, data)
    elif mode is 'p':
        pickle_writer(path, data)
    elif mode is 'c':
        crypt_writer(path, data)


def head_tail(path, mode=None):
    head, tail = os.path.split(path)
    if mode is 'h':
        return head
    if mode is 't':
        return tail
    else:
        return head, tail


def up_folder(path):
    return head_tail(head_tail(path, 'h'), 'h')
