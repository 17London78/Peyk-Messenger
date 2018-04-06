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


def reader(path):
    with open(path, 'r') as reader:
        message = reader.read()
    return message


def binaryReader(path):
    with open(path, 'rb') as reader:
        message = reader.read()
    return message


def writer(path, message):
    with open(path, 'w+') as writer:
        writer.write(message)


def binaryWriter(path, message):
    with open(path, 'wb') as writer:
        writer.write(message)


def headTail(path):
    head, tail = os.path.split(path)
    File = tail
    head = head
    return (File, head)
