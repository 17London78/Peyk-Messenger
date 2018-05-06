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
from threading
import pickle
import tkinter
from Files.Ciphers import CipherManager
from Files.Assets import BasicFunctions


def main():
    def start():
        receive_thread = Thread(target=receive)
        receive_thread.start()
        tkinter.mainloop()

    def run():
        if password is 'None':
            start()
        else:
            client.sendall(password.encode('utf-8'))
            start()

    def send(event=None):
        data = my_msg.get()
        my_msg.set("")
        encrypt = CipherManager.sendEnc(data, username, pubKeyPath,
                                        c_pubkeypath, privKeyPath,
                                        privKeyPassword)
        data = encrypt.sendEnc()
        encryptedData = pickle.dumps(data)
        client.sendall(encryptedData)

    def isEncrypted(data):
        try:
            data = pickle.loads(data)
            return True
        except ValueError:
            return False

    def receive():
        welcome = "Connection to : " + ip + ":" + str(port) + " established"
        msg_list.insert(tkinter.END, welcome)
        while True:
            data = client.recv(10240)
            if data != "" or data:
                if isEncrypted(data) is False:
                    message = data.decode('utf_8')
                    msg_list.insert(tkinter.END, message)
                else:
                    try:
                        encryptedData = pickle.loads(data)
                        dec = CipherManager.recDec(encryptedData, username,
                                                   pubKeyPath, c_pubkeypath,
                                                   privKeyPath, privKeyPassword)
                        plaintext = dec.decrypt()
                        msg_list.insert(tkinter.END, plaintext)
                    except (CipherManager.MessageTagDoesNotMatch or
                            CipherManager.MessageSignatureDoesNotMatch):
                        msg = """
    ======================================================
    |+          Message is not AUTHENTICATED!           +|
    |+           terminating connection ...             +|
    ======================================================
    """
                        msg_list.insert(tkinter.END, msg)

    port = {}
    ip = '{}'
    password = '{}'
    username = '{}'
    pubKeyPath = '{}'
    privKeyPath = '{}'
    privKeyPassword = '{}'
    c_pubkeypath = '{}'
    client = socket.socket()
    client.connect((ip, port))

    Window = tkinter.Tk()
    Window.title("Peyk Messenger")

    messages_frame = tkinter.Frame(Window)
    # For the messages to be sent.
    my_msg = tkinter.StringVar()
    my_msg.set("")
    # To navigate through past messages.
    scrollbar = tkinter.Scrollbar(messages_frame)
    # Following will contain the messages.
    msg_list = tkinter.Listbox(
        messages_frame, height=25, width=70, yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
    msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
    msg_list.pack()
    messages_frame.pack()

    entry_field = tkinter.Entry(Window, textvariable=my_msg)
    entry_field.bind("<Return>", send)
    entry_field.pack()
    send_button = tkinter.Button(Window, text="Send", command=send)
    send_button.pack()

    run()

class GUI:
    def __init__(self):
        self.port = {}
        self.ip = '{}'
        self.buffer = 10240  # Not optimistic yet
        self.username = '{}'
        self.pub_key = BasicFunctions.reader('{}', 'b')
        self.priv_key = BasicFunctions.reader('{}', 'b')
        self.priv_key_password = '{}'
        self.client_key = {}
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.client.connect((self.ip, self.port))
        self.send_encrypt = CipherManager.Send(self.username, self.pub_key, self.client_key, self.priv_key, self.priv_key_password)
        self.receive_decrypt = CipherManager.Receive(self.username, self.pub_key, self.client_key, self.priv_key, self.priv_key_password)
        self.client_tag = '<$CLIENT$>'
        self.messageTypes_tagList = ['TXT', 'IMG', 'VOICE', 'FILE']

    def _start(self):
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
        send_button = tkinter.Button(self.Window, text="Send",
                                     command=self._send)
        send_button.pack()
        self.Window.protocol("WM_DELETE_WINDOW", self._on_closing)
        self.Window.mainloop()

    def _on_closing(self, mode='x'):
        def action():
            self.client.shutdown(socket.SHUT_RDWR)
            self.client.close()
            self.Window.destroy()
            sys.exit(2)
        if mode is 'x':
            if tkinter.messagebox.askokcancel("Quit", "Do you want to quit?"):
                action()
        elif mode is 'e':
            action()

    def _send(self, event=None):
        """This function responsible for encrypting and sending messages"""
        data = self.my_msg.get()
        self.my_msg.set("")
        cipher_data = self.send_encrypt.encrypt(data, 'p2p')
        message = (self.client_tag, self.messageTypes_tagList[0], cipher_data)
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
                # Clean up and exit after 10 seconds
                time.sleep(10)
                self._on_closing('e')
