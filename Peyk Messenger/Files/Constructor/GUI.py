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
from threading import Thread
import pickle
import tkinter
from Files.Ciphers import CipherManager


def main():
    def start():
        receive_thread = Thread(target=receive)
        receive_thread.start()
        tkinter.mainloop()

    def run():
        if password is 'None':
            start()
        else:
            client.send(password.encode('utf-8'))
            start()

    def send(event=None):
        data = my_msg.get()
        my_msg.set("")
        encrypt = CipherManager.sendEnc(data, username, pubKeyPath,
                                        c_pubkeypath, privKeyPath,
                                        privKeyPassword)
        data = encrypt.sendEnc()
        encryptedData = pickle.dumps(data)
        client.send(encryptedData)

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
