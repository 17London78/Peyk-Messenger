#!/usr/bin/python3
"""
Peyk Secure Encrypted Messenger
GNU AGPL 3.0 Licensed
Copyright (C) 2018 17London78 Inc.
=========================================
A library for GUI
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

import sys
import time
import socket
import pickle
import tkinter
import threading
from Files.Ciphers import CipherManager
from Files.Assets import BasicFunctions

class GUI:
    def __init__(self, ip, port, buffer, username, pub_key_path, prive_key_path, priv_key_password, client_key):
        self.port = port
        self.ip = ip
        self.buffer = buffer
        self.username = username
        self.pub_key = BasicFunctions.reader(pub_key_path, 'b')
        self.priv_key = BasicFunctions.reader(prive_key_path, 'b')
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.client.connect((self.ip, self.port))
        self.send_encrypt = CipherManager.Send(self.username, self.pub_key, client_key, self.priv_key, priv_key_password)
        self.receive_decrypt = CipherManager.Receive(self.username, self.pub_key, client_key, self.priv_key, priv_key_password)
        self.server_tag = '<$SERVER$>'
        self.client_tag = '<$CLIENT$>'
        self.message_tag = ['TXT', 'IMG', 'VOICE', 'FILE']

    def run(self):
        receive_thread = threading.Thread(target=self._receive)
        receive_thread.start()
        self.Window = tkinter.Tk()
        app_name = "Peyk Messenger | Private Chat"
        self.Window.title(app_name)
        # Creating message frame
        messages_frame = tkinter.Frame(self.Window)
        # For the messages to be sent.
        self.my_msg = tkinter.StringVar()
        self.my_msg.set("")
        # To navigate through past messages.
        scrollbar = tkinter.Scrollbar(messages_frame)
        # Following will contain the messages.
        self.msg_list = tkinter.Listbox(
            messages_frame, height=25, width=70, yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
        self.msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
        self.msg_list.pack()
        messages_frame.pack()

        entry_field = tkinter.Entry(self.Window, textvariable=self.my_msg)
        entry_field.bind("<Return>", self._send)
        entry_field.pack()
        send_button = tkinter.Button(self.Window, text="Send", command=self._send)
        send_button.pack()
        self.Window.protocol("WM_DELETE_WINDOW", self._on_closing)
        self.Window.mainloop()

    def _on_closing(self, mode='x'):
        def close():
            self.client.shutdown(socket.SHUT_RDWR)
            self.client.close()
            self.Window.destroy()
            sys.exit(2)
        if mode is 'x':
            if tkinter.messagebox.askokcancel("Quit", "Do you want to quit?"):
                close()
        elif mode is 'e':
            close()

    def _send(self, event=None):
        """This function responsible for encrypting and sending messages"""
        data = self.my_msg.get()
        self.my_msg.set("")
        cipher_data = self.send_encrypt.encrypt(data, 'p2p')
        message = (self.client_tag, self.message_tag[0], cipher_data)
        self.client.sendall(pickle.dumps(message))

    def _receive(self):
        """This function responsible for receiving messeges and decryption"""
        while True:
            data = self.client.recv(self.buffer)
            # If socket could receive any data
            if data:
                raw_tuple = pickle.loads(data)
                # If message sender is the server
                if raw_tuple[0] == self.server_tag:
                    # Show it
                    self.msg_list.insert(tkinter.END, raw_tuple[1])
                # If message sender is a client
                elif raw_tuple[0] == self.client_tag:
                    try:
                        # Try to decrypt
                        plain_data = self.receive_decrypt.decrypt(raw_tuple[2], 'p2p')
                        # Check if it's a text message
                        if raw_tuple[1] == self.messageTypes_tagList[0]:
                            self.msg_list.insert(tkinter.END, plain_data)
                        # Check if it's an image
                        elif raw_tuple[1] == self.messageTypes_tagList[1]:
                            pass  # [ TODO future features]
                        # Check if it's a voice
                        elif raw_tuple[1] == self.messageTypes_tagList[2]:
                            pass  # [ TODO future features]
                        # Check if it's a file
                        elif raw_tuple[1] == self.messageTypes_tagList[3]:
                            pass  # [ TODO future features]
                    # If message is not authenticated with sender
                    except CipherManager.MessageSignatureDoesNotMatch:
                        message = 'An unauthenticated message received'
                        self.msg_list.insert(tkinter.END, message)
                    # If message is not authenticated with sender
                    except CipherManager.MessageTagDoesNotMatch:
                        message = 'An unauthenticated message received'
                        self.msg_list.insert(tkinter.END, message)
            # If socket failed to receive anything.
            else:
                # Print server down message to GUI widget
                message = "Server down!"
                self.msg_list.insert(tkinter.END, message)
                # Clean up and exit after 5 seconds
                time.sleep(5)
                self._on_closing('e')
