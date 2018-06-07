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

import os
import sys
import time
import errno
import socket
import pickle
import tkinter
import threading
from ..Ciphers import CipherManager
from ..Assets import BasicFunctions, Texts


class GUI:
    def __init__(self, ip, port, buffer, username, keys, priv_key_password):
        self.ip = ip
        self.port = port
        self.buffer = buffer
        self.username = username
        self.user_keys = keys
        self.priv_key_password = priv_key_password
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.client.connect((self.ip, self.port))
        self.server_tag = '<$SERVER$>'
        self.client_tag = '<$CLIENT$>'
        self.message_tag = ['TXT', 'IMG', 'VOICE', 'FILE']

    def _start(self):
        receive_thread = threading.Thread(target=self._receive)
        receive_thread.start()
        self.Window = tkinter.Tk()
        app_name = "Peyk Messenger | {}".format(self.gui_type)
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

    def _exit(self):
        print("Connection lost!")
        self.client.shutdown(socket.SHUT_RDWR)
        self.client.close()
        sys.exit(2)


class Private(GUI):
    def __init__(self, ip, port, buffer, username, keys, priv_key_password, client_key):
        super(Private, self).__init__(ip, port, buffer, username, keys, priv_key_password)
        self.send_encrypt = CipherManager.Send(self.username, self.user_keys[0], self.user_keys[1], self.priv_key_password, client_key)
        self.receive_decrypt = CipherManager.Receive(self.username, self.user_keys[0], self.user_keys[1], self.priv_key_password, client_key)
        self.gui_type = 'Private Chat'

    def run(self):
        self._start()

    def _send(self, event=None):
        """This function responsible for encrypting and sending messages"""

        data = self.my_msg.get()
        self.my_msg.set("")
        cipher_data = self.send_encrypt.encrypt(data, 'p2p')
        message = (self.client_tag, self.message_tag[0], cipher_data)
        self.client.sendall(pickle.dumps(message))

    def _receive(self):
        """This function responsible for receiving messages and decryption"""

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
                        if raw_tuple[1] is self.message_tag[0]:
                            self.msg_list.insert(tkinter.END, plain_data)
                        # Check if it's an image
                        elif raw_tuple[1] is self.message_tag[1]:
                            pass  # [ TODO future features]
                        # Check if it's a voice
                        elif raw_tuple[1] is self.message_tag[2]:
                            pass  # [ TODO future features]
                        # Check if it's a file
                        elif raw_tuple[1] is self.message_tag[3]:
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


class Group(GUI):
    def __init__(self, ip, port, buffer, server_name, server, server_keys, password, username, keys, priv_key_password):
        super(Private, self).__init__(ip, port, buffer, username, keys, priv_key_password)
        self.server_name = server_name
        self.password = password
        self.receiver_pub_keys = dict()
        self.server_manager = server
        server = self.server_manager.access_server(self.server_name)
        self.server_pubkey = {1: [server.keys[0], None], 2: [server.keys[1], None]}
        if self.server_pubkey[1][0] is not None:
            self.server_pubkey[1][1] = 1
        else:
            self.server_pubkey[1][1] = 0
        if self.server_pubkey[2][0] is not None:
            self.server_pubkey[2][1] = 1
        else:
            self.server_pubkey[2][1] = 0
        self.img_path, self.voice_path, self.file_path = self._path_builder()
        self.codes = ["<join>", "<list>", "<manual>", "<quit>"]
        self.new_client_tag = '<$NewKey$>'
        self.new_dict_tag = '<$NewDict$>'
        self.gui_type = 'Group Chat'

    def _path_builder(self):
        """ Creating directories for the group server """

        # Finding the path to this file's directory
        file = os.path.dirname(os.path.abspath(__file__))
        # Moving to /Data/user_name"
        up_folder = BasicFunctions.head_tail(file)
        data_folder = os.path.join(up_folder, 'Data')
        location = os.path.join(data_folder, self.username)
        # Joining path "user's directory/Group Servers"
        servers = os.path.join(location, 'Group Servers')
        # Check if 'Group Servers' directory already exits
        if os.path.isdir(servers):
            # Joining path "this file's directory/Group Servers/"this server's
            # name"
            server = os.path.join(servers, self.server_name)
            # Check if "this server's name" already exits
            if os.path.isdir(server):
                # Joining all requires paths:
                # this server's name/IMG >>> a folder to save incoming images
                # this server's name/VOICE >>> a folder to save incoming sounds
                # this server's name/FILE >>> a folder to save incoming files
                img = os.path.join(server, 'IMG')
                voice = os.path.join(server, 'VOICE')
                file = os.path.join(server, 'FILE')
                loop = [img, voice, file]
                for element in loop:
                    # If path already exists
                    if os.path.isdir(element):
                        # Go to next element
                        pass
                    # If path doesn't exist
                    else:
                        try:
                            # Create directory
                            os.makedirs(element)
                        # Handling errors
                        except OSError as e:
                            if e.errno != errno.EEXIST:
                                raise
                return img, voice, file
            # If path doesn't exist
            else:
                # Create directory
                try:
                    os.makedirs(server)
                # Handling errors
                except OSError as e:
                    if e.errno != errno.EEXIST:
                        raise
                # Start again
                return self._path_builder()
        # If path doesn't exist
        else:
            # Create directory
            try:
                os.makedirs(servers)
            # Handling errors
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise
            # Start again
            return self._path_builder()

    def run(self):
        """Preparing user for Sign up/Login and after establishing connection
        to the server starting GUI"""
        state = self.server_pubkey[1][1], self.server_pubkey[2][1]
        self.client.sendall(pickle.dumps(state))
        if state[0] is 0:
            data = self.client.recv(self.buffer)
            if data:
                pub_key = pickle.loads(data)
                self.server_manager.add_key(self.server_name, key_one=pub_key)
                self.server_pubkey[1][0] = pub_key
            else:
                self._exit()
        if state[1] is 0:
            data = self.client.recv(self.buffer)
            if data:
                pub_key = pickle.loads(data)
                self.server_manager.add_key(self.server_name, key_two=pub_key)
                self.server_pubkey[1][0] = pub_key
            else:
                self._exit()
        self.send_to_server = CipherManager.Send(recipient_pubkey=self.server_pubkey[1][0])
        self.send_to_client = CipherManager.Send(recipient_pubkey=self.server_pubkey[2][0])

        if self.password is None:
            state = self._entrance_to_server()
            if state:
                self._start()
        else:
            passphrase = self.send_to_server.encrypt(self.password, 'p2s')
            self.client.sendall(pickle.dumps(passphrase))
            data = self.client.recv(self.buffer)
            if data:
                state = pickle.loads(data)
                if state is 1:
                    state = self._entrance_to_server()
                    if state:
                        self._start()
                else:
                    print("Wrong password! you can't connect to this server.")
                    self._exit()
            else:
                self._exit()

    def _entrance_to_server(self):
        status = self.server_manager.query(self.server_name, self.username)
        if status is 0:
            state = self._signup()
            return state
        else:
            state = self._login()
            return state

    def _signup(self):
        text = Texts.SignUp
        print(text)
        self.username = input(Texts.UserName)
        password = input(Texts.Password)
        publicKey = BasicFunctions.binaryReader(self.pubKeyPath)
        packet = (self.username, password, publicKey)
        packet = self._encCycle(packet)
        packet = pickle.dumps(packet)
        self.client.sendall(packet)
        data = self.client.recv(self.buffer)
        if data:
            respond = pickle.loads(data)
            if respond is 0:
                print(Texts.SignUpSuccess)
                self._login()
            elif respond is 1:
                print(Texts.SignUpUsrExist)
                self._signup()
            elif respond is 2:
                print(Texts.SignUpPassErr)
                self._signup()
        else:
            self._exit()

    def _login(self):
        """A function for handling login into a server"""
        # Importing login texts to show
        text = Texts.login
        print(text)
        self.username = input(Texts.UserName)
        password = input(Texts.Password)
        # Packing information
        packet = (self.username, password)
        # Encrypting
        packet = self._encCycle(packet)
        # Sending to server
        packet = pickle.dumps(packet)
        self.client.sendall(packet)
        # Receiving respond from server
        data = self.client.recv(self.buffer)
        # If any data received
        if data:
            respond = pickle.loads(data)
            # Successfull login
            if respond is 0:
                print(Texts.login_success)
                return True
            # Username or password is incorrect
            elif respond is 1:
                print(Texts.login_error)
                self._login()
            # User is already in the server via another app
            elif respond is 2:
                print(Texts.login_already_in)
                self._login()
        # If no data received, then connection is lost; close socket and exit.
        else:
            self._exit()

    def _encCycle(self, Tuple):
        """ Encrypting elements inside a tuple with server's public key"""
        List = list(Tuple)
        for i in range(0, len(List)-1):
            sendEnc = CipherManager.sendEnc(data=List[i],
                                            c_pubkey=self.serverpubkeybinary)
            List[i] = sendEnc.encrypt('p2s')
        return tuple(List)

    def _send(self, event=None):
        """This function responsible for encrypting and sending messages"""
        data = self.my_msg.get()
        self.my_msg.set("")
        msg = data.split()
        if msg[0] in self.codes:
            sendEnc = CipherManager.sendEnc(data,
                                            c_pubkey=self.serverpubkeybinary)
        else:
            sendEnc = CipherManager.sendEnc(data, self.username,
                                            self.pubKeyPath,
                                            self.c_pubkeys,
                                            self.privKeyPath,
                                            self.privKeyPassword)
            cipher_data = sendEnc.encrypt('p2g')
            message = (self.client_tag, self.messageTypes_tagList[0],
                       cipher_data)
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
                    # Check if it's a new single key
                    if raw_tuple[1] == self.newClient_tag:
                        # Adds new key of new client to key dictionary
                        self.c_pubkeys[raw_tuple[2]] = raw_tuple[3]
                    # Check if it's a new key dictionary
                    elif raw_tuple[1] == self.newDict_tag:
                        # Rewriting existing key dictionary with
                        # new one.
                        new_dict = raw_tuple[2]
                        self.c_pubkeys = new_dict.copy()
                    # If non of above, then it's an text message from
                    # the server
                    else:
                        # Show it
                        self.msg_list.insert(tkinter.END, raw_tuple[1])
                # If message sender is a client
                elif raw_tuple[0] == self.client_tag:
                    # Creating an instance of an object for decryption
                    recDec = CipherManager.recDec(raw_tuple[2], self.username,
                                                  c_pubkey=self.c_pubkeys,
                                                  privKeyPath=self.privKeyPath,
                                                  privKeyPassword=self.privKeyPassword)
                    try:
                        # Try to decrypt
                        plain_data = recDec.decrypt()
                        # Check if it's a text message
                        if raw_tuple[1] == self.messageTypes_tagList[0]:
                            self.msg_list.insert(tkinter.END, plain_data)
                        # Check if it's an image
                        elif raw_tuple[1] == self.messageTypes_tagList[1]:
                            pass  # [TODO future features]
                        # Check if it's a voice
                        elif raw_tuple[1] == self.messageTypes_tagList[2]:
                            pass  # [TODO future features]
                        # Check if it's a file
                        elif raw_tuple[1] == self.messageTypes_tagList[3]:
                            pass  # [TODO future features]
                    # If message is not authenticated with sender
                    except CipherManager.MessageSignatureDoesNotMatch:
                        message = 'An unauthenticated message recieved'
                        self.msg_list.insert(tkinter.END, message)
                    # If message is not authenticated with sender
                    except CipherManager.MessageTagDoesNotMatch:
                        message = 'An unauthenticated message recieved'
                        self.msg_list.insert(tkinter.END, message)
            # If socket failed to receive anything.
            else:
                # Print server down message to GUI widget
                message = "Server down!"
                self.msg_list.insert(tkinter.END, message)
                # Clean up and exit after 10 seconds
                time.sleep(10)
                self._on_closing('e')
