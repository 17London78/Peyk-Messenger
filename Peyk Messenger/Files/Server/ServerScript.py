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
import socket
import time
import threading


class server:
    def __init__(self, tcp_ip, tcp_port, buffer_size, servername, password=None):
        self.servername = servername
        self.ip = tcp_ip
        if type(tcp_port) is str:
            tcp_port = int(tcp_port)
        self.port = tcp_port
        if password is not None:
            self.password = password
        self.buffer = buffer_size
        self.socket = []
        self.CLIENTS = {}
        self.COUNTER = 0

    def startServer(self):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.ip, self.port))
            server_socket.listen(128)
            self.socket.append(server_socket)
            while 1:
                client_socket, addr = server_socket.accept()
                self.COUNTER += 1
                c_id = self.COUNTER
                self.CLIENTS[c_id] = client_socket
                self._validator(client_socket, c_id)

        except socket.error:
            raise ServerFatalError  # Do somthing after

    def _validator(self, client_socket, c_id):
        if self.password is None:
            threading.Thread(
                target=self._transformerOne, args=(
                    client_socket,
                    c_id,
                )).start()
        else:
            threading.Thread(
                target=self._transformerTwo, args=(
                    client_socket,
                    c_id,
                )).start()

    def _SSAlogin(self, password):
        return self.password == password

    def _transformerOne(self, client_socket, c_id):
        msg1 = 'FROM SERVER: you are now connected to @{}!'.format(
            self.servername)
        client_socket.send(msg1.encode('utf-8'))

        while True:
            try:
                data = client_socket.recv(self.buffer)
                self._send(data)
                if not data:
                    break
            except ConnectionResetError:
                break

        del self.CLIENTS[c_id]
        self.COUNTER -= 1
        client_socket.close()

    def _transformerTwo(self, client_socket, c_id):
        data = client_socket.recv(self.buffer)
        if self._SSAlogin(data.decode('utf-8')):
            self._transformerOne(client_socket, c_id)
        else:
            msg1 = """
========================================================================
|+                            Incorrect password.                     +|
|+  This is a private server you need to provide password to connect  +|
========================================================================


                        """
            msg2 = 'Terminating connection...'
            error = '{}{}'.format(msg1, msg2)
            client_socket.send(error.encode('utf-8'))
            del self.CLIENTS[c_id]
            self.COUNTER -= 1
            time.sleep(2)
            client_socket.close()

    def _send(self, data):
        for client in self.CLIENTS:
            c_socket = self.CLIENTS[client]
            c_socket.send(data)


class ServerFatalError(Exception):
    pass
