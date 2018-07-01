#!/usr/bin/python3
"""
Peyk Secure Encrypted Messenger
GNU AGPL 3.0 Licensed
Copyright (C) 2018 17London78 Inc.
=========================================
"""
__author__ = "Mohammad Mahdi Baghbani Pourvahid"
__copyright__ = "Copyright (C) 2018 17London78 Inc."
__credits__ = ["Jadi Mirmirani, Xysun, Al Sweigart"]
__license__ = "AGPL 3.0"
__maintainer__ = "Mohammad Mahdi Baghbani Pourvahid"
__email__ = "MahdiBaghbani@Protonmail.com"
__version__ = "0.1-beta"
__status__ = "Development"


import sys
from Files import App
from Files.Assets import Util


LIBRARIES = ['Crypto']


def prepare(library):
    sys_info = Util.check_system()
    libraries_status = {i: Util.check_module(i) for i in library}
    return sys_info, libraries_status


def check(library_status):
    if all(library_status):
        return True
    else:
        return False


def main():
    data = prepare(LIBRARIES)
    if check(data[1]):
        App(data[0]).run()
    else:
        print()
        sys.exit()


if __name__ == '__main__':
    main()
