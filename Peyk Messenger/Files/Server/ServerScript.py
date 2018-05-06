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

import socket
import select
import pickle
from Files.Assets import Texts


class Server:
    """ Main class for initialising a server """

    def __init__(self, tcp_ip, tcp_port, buffer_size):
        if type(tcp_port) is str:
            tcp_port = int(tcp_port)
        self.ip = tcp_ip
        self.port = tcp_port
        self.buffer = buffer_size

    def start(self):
        """ The main function that starts server sockets and manages I/O """

        # Creating server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.ip, self.port))
        server_socket.listen(5)
        # Creating two lists for managing sockets
        connection_list = list()
        client_list = list()
        # Adding server socket to connection list
        connection_list.append(server_socket)
        # Welcome message
        welcome = pickle.dumps(Texts.server_welcome.format(self.ip, self.port))
        while True:
            # Initialising select method
            read, write, error = select.select(connection_list, [], [])
            for sock in read:
                #  New connection
                if sock is server_socket:
                    client_raw, address = server_socket.accept()
                    # Adding socket to connection list and client list
                    client_raw.sendall(welcome)
                    connection_list.append(client_raw)
                    client_list.append(client_raw)
                # New message
                else:
                    # Receiving data from socket
                    data = sock.socket.recv(self.buffer)
                    # If any data received
                    if data:
                        for client in client_list:
                            client.sendall(data)
                    # If no data received
                    else:
                        sock.shutdown(socket.SHUT_RDWR)
                        sock.socket.close()
                        connection_list.remove(sock)
                        client_list.append(sock)
            # Close error sockets
            for sock in error:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
                connection_list.remove(sock)
                client_list.append(sock)
