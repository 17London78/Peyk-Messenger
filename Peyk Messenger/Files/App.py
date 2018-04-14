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
import sys
import time
from Files import CAS, Auth
from Files.Server import ServerManager, SelfServerAdmin
from Files.Constructor import Constructor
from Files.Assests import BasicFunctions


class app():
    def __init__(self):
        self.CAS = CAS.CAS()
        self.username = ''
        self.intro_choices = {
            "1": self._signUp,
            "2": self._signIn,
            "3": self._quit
        }
        self.dashboard_choices = {
            "1": self._connect_to_server,
            "2": self._register_server,
            "3": self._beServerRun,
            "4": self._connect_to_client,
            "5": self._client_options,
            "6": self._changePassword,
            "7": self._signOut,
            "8": self._quit
        }
        self._beServerRun_choices = {
            "1": self._start_be_server,
            "2": self._register_server,
            "3": self._server_edit,
            "4": self._server_remove,
            "5": self._dashboard,
            "6": self._quit
        }
        self._clientOptionsRun_choices = {
            "1": self._register_client,
            "2": self._client_edit,
            "3": self._client_remove,
            "4": self._dashboard,
            "5": self._quit
        }

    def _intro_menu(self):
        print("""#### Welcome to Peyk Messenger v0.1 [BETA] ####

Select a number from this options:

1. signUp
2. signIn
3. Quit
""")

    def _run(self):
        while True:
            self._intro_menu()
            self._run2()

    def _run2(self):
        choice = input('Enter a valid choice:\n>')
        action = self.intro_choices.get(choice)
        if action == self._quit:
            action('i')
        if action:
            action()
        else:
            print("{} is Not a valid choice".format(choice))
            print()
            time.sleep(0.5)
            self._run2()

    def _signUp(self):
        if len(self.CAS.cas.users) == 0:
            print('>>>> Sign up window <<<<')
            print()
            username = input('Enter your username:\n>')
            password = input('Enter your password:\n>')
            try:
                self.CAS.signUp(username, password)
                time.sleep(0.25)
                print("""
========================================================
|+  Your account has been activated, log in please.  +|
========================================================


""")
                print()
                time.sleep(0.5)
                self._signIn()
            except Auth.PasswordTooShort:
                time.sleep(0.5)
                print("""
===================================================
|+          your password is TOO SHORT!           +|
|+  your password must be at least 6 characters.  +|
====================================================


""")
                time.sleep(0.5)
                self._signUp()
        else:
            time.sleep(0.5)
            print("""
=========================================================================
|+  There is an account in app already, you can't register a new one!  +|
|+                             you have to sign in                     +|
=========================================================================


""")

            self._run2()

    def _signIn(self):
        if len(self.CAS.cas.users) != 0:
            print('>>>> Login [window] <<<<')
            print()
            time.sleep(0.25)
            username = input('Enter your username:\n>')
            password = input('Enter your password:\n>')
            try:
                verify = self.CAS.signIn(username, password)
            except Auth.InvalidUsername or Auth.InvalidPassword:
                time.sleep(0.5)
                print("""
    ===================================
    |+  WRONG username or password!  +|
    ===================================


    """)
                time.sleep(0.5)
                self._run()
            if verify is True:
                self.server1st = ServerManager.Server1st()
                self.server2nd = ServerManager.Server2nd()
                self.clientlist = list(self.CAS.cas.clients.keys())
                self.username = username
                self.password = self.CAS.cas.users[username].password
                self.pubKeyPath = self.CAS.cas.users[username].pubpath
                self.privKeyPath = self.CAS.cas.users[username].privpath
                time.sleep(0.25)
                print("""
    ==================
    |+  Logged in!  +|
    ==================


                    """)
                time.sleep(0.25)
                self._dashboard()
        else:
            time.sleep(0.25)
            print("""
    =============================================================
    |+  There is not any accounts in app , you can't sign in!  +|
    |+              you have to SIGN UP first!!!               +|
    =============================================================


    """)
            time.sleep(0.5)
            self._run2()

    def _dashboard(self):
        while True:
            self._dashboard_menu()
            self._dashboard2()

    def _dashboard2(self):
        choice = input('Enter a valid choice from dashboard menu:\n>')
        action = self.dashboard_choices.get(choice)
        if action:
            if action == self._register_server:
                action(self._dashboard, self.server1st)
            else:
                time.sleep(0.5)
                action()
        else:
            print("{} is NOT a valid choice".format(choice))
            print()
            time.sleep(0.5)
            self._dashboard2()

    def _dashboard_menu(self):
        print("""#+++>>> Wlecome to your dashboard dear {} <<<+++#

Select a number from this options:
1. Connect to a server
2. Register a server
3. Become a server
4. Connect to a client
5. Client options
6. Change password
7. Sign out
8. Quit
""".format(self.username))

    def _connect_to_server(self):
        print('>>>> Connect to a Server [window] <<<<')
        print()
        targetDatabase = self.server1st.server.serverU.servers
        if len(targetDatabase) == 0:
            print("You didn't setup any server configuration before:")
            time.sleep(0.5)
            self._dashboard()
        else:
            print('Which server do you want to connect?')
            server_data = self._serverChoice(targetDatabase)

    def _register_server(self, returnChoice, database):
        print('>>>> Server registering [window] <<<<')
        print()
        time.sleep(0.25)
        servername = input("Enter server's name:\n>")
        ip = input("""Enter server's IPv4 addrress: \n>""")
        port = input("Enter server's port number:\n>")
        if port == '':
            time.sleep(0.25)
            print()
            print('You must enter a port number for server!')
            print()
            time.sleep(1)
            self._register_server(returnChoice, database)
        password = input("""Enter server's password:
(leave it empty if it's a public server)
>""")
        if len(password) > 0 and len(password) < 6:
            print("""
===================================================
|+          your password is TOO SHORT!           +|
|+  your password must be at least 6 characters.  +|
====================================================


""")
        if password == '':
            password = None
        client = input("""If it's a server for private E2E chat, enter client name:
>""")
        if client == '':
            client = None
        try:
            database.server.addServer(servername, ip, port, password, client)
            time.sleep(0.5)
            print("""
=======================================
|+  'Server registered successfuly!'  +|
=======================================


            """)
            time.sleep(0.5)
            returnChoice()
        except Auth.UsernameAlreadyExists:
            time.sleep(0.5)
            print("""
==================================
|+  Server name already exists  +|
==================================


            """)
            time.sleep(0.5)
            self._register_server(returnChoice, database)

    def _beServerRun(self):
        while True:
            self._beServerRunShow()
            self._beServerRun2()

    def _beServerRun2(self):
        targetDatabase = self.server2nd.server.serverU
        choice = input('Enter a valid choice from menu:\n>')
        action = self._beServerRun_choices.get(choice)
        if action:
            if action == self._register_server:
                time.sleep(0.5)
                action(self._beServerRun, self.server2nd)
            elif action == (self._dashboard or self._quit):
                time.sleep(0.5)
                action()
            else:
                time.sleep(0.5)
                action(targetDatabase)
        else:
            print("{} is NOT a valid choice".format(choice))
            print()
            time.sleep(0.5)
            self._beServerRun2()

    def _beServerRunShow(self):
        print(""">>>> Become a Server [window] <<<<

Select a number from this options:
1. Start a server
2. Register a server
3. Edit a server
4. Delete a server
5. Back to dashboard
6. Quit
    """)

    def _start_be_server(self, targetDatabase):
        time.sleep(0.25)
        if len(targetDatabase.servers) == 0:
            print("You didn't setup any server configuration before:")
            self._beServerRun2()
        else:
            print('Which server do you want to activate?')
            time.sleep(0.5)
            server_data = self._server_tool(targetDatabase,
                                            self._choiceToConnect, 'connect')

            server = SelfServerAdmin.SSA(server_data, 10240, self.username,
                                         self.pubKeyPath, self.privKeyPath,
                                         self.password,
                                         self._serverToclient(server_data[1]))
            server._start_server()
            self._barAnimation()
            time.sleep(0.5)
            from Files import GUI
            GUI.main()
            time.sleep(1)
            print('You will redirect to dashboard')
            time.sleep(0.5)
            self.GUICleaner()
            self._dashboard()

    def GUICleaner(self):
        BasicFunctions.writer('Files/GUI.py', '#!/usr/bin/python3')

    def _serverToclient(self, client):
        try:
            clientobject = self.CAS.cas.clients[client]
            return clientobject.pubKeyPath
        except KeyError:
            print("The client Associated with this server doesn't exist!")
            print("You have to check to see if client name in server configured correctly.")
            time.sleep(0.5)
            self._beServerRun()

    def _barAnimation(self):
        time.sleep(0.5)
        print('\n#>>> Initalization completed <<<#\n')

    def _serverPrinter(self, targetDatabase):
        targetDatabase = targetDatabase.servers
        counter = 1
        server_dic = {}
        for server in targetDatabase:
            server_dic[str(counter)] = server
            print('{}. {}'.format(counter, server))
            counter += 1
        return server_dic

    def _server_tool(self, targetDatabase, mainprocess=None, mode=None):
        time.sleep(0.5)
        server_dic = self._serverPrinter(targetDatabase)
        server_data = self._serverChoice(targetDatabase, server_dic,
                                         mainprocess, mode)
        if mode == 'connect':
            return server_data

    def _serverChoice(self,
                      targetDatabase,
                      server_dic,
                      mainprocess=None,
                      mode=None):
        choice = input('Enter a valid choice from server list:\n>')
        server = server_dic.get(choice)
        if server:
            if mode is 'connect':
                targetDatabase = targetDatabase.servers
                serverobject = targetDatabase[server]
                return mainprocess(serverobject)
            else:
                mainprocess(targetDatabase, server)
        else:
            print("{} is NOT a valid choice".format(choice))
            print()
            time.sleep(0.5)
            self._serverChoice(targetDatabase, server_dic, mainprocess, mode)

    def _choiceToConnect(self, serverobject):
        tag = serverobject.tag
        if tag == 'public server':
            return (serverobject.connect, serverobject.client)
        else:
            return (serverobject.connect, serverobject.client,
                    serverobject.password)

    def _server_edit(self, targetDatabase):
        self._server_tool(targetDatabase, self._server_edit_process)

    def _server_edit_process(self, targetDatabase, server):
        print('>>>> Server editing [window] <<<<')
        print()
        print("You can just press enter if you don't want to change")
        time.sleep(0.25)
        name = input("""Change server's new name: \n>""")
        if name == '':
            name = None
        ip = input("""Change server's new IPv4 addrress: \n>""")
        if ip == '':
            ip = None
        port = input("Change server's new port number:\n>")
        if port == '':
            port = None
        password = input("""Change server's new password:
>""")
        if len(password) > 0 and len(password) < 6:
            print("""
===================================================
|+          your password is TOO SHORT!           +|
|+  your password must be at least 6 characters.  +|
====================================================


""")
        if password == '':
            password = None

        client = input("""If it's a server for E2E chat, enter client name:
>""")
        if client == '':
            client = None

        targetDatabase.serverEdit(server, name, ip, port, password)
        time.sleep(0.5)
        print("""
===========================================
|+  Server profile updated successfuly!  +|
===========================================


            """)
        time.sleep(0.5)
        self._beServerRun()

    def _server_remove(self, targetDatabase):
        self._server_tool(targetDatabase, self._server_remove_process)

    def _server_remove_process(self, targetDatabase, server):
        targetDatabase.delete_server(server)
        time.sleep(0.5)
        print("""
===========================================
|+  Server profile removed successfuly!  +|
===========================================


            """)
        time.sleep(0.5)
        self._beServerRun()

# Client Section
# Connect to client

    def _connect_to_client(self):
        print('>>>> Client connect [window] <<<<')
        print()
        time.sleep(0.25)
        self._client_tool(self._client_filter(), self._client_connect,
                          self._dashboard2)

    def _client_tool(self, target, mainprocces, returnTarget):
        self.clientlist = list(self.CAS.cas.clients.keys())
        if len(self.clientlist) != 0:
            time.sleep(0.5)
            client_dic = self._client_print(target)
            self._client_run(client_dic, mainprocces)

        else:
            time.sleep(0.5)
            print("""
=======================================================
|+         There is not any clients available.       +|
|+           You need to register a client           +|
=======================================================


            """)
            time.sleep(1)
            returnTarget()

    def _client_print(self, target):
        counter = 1
        client_dic = {}
        for client in target:
            client_dic[str(counter)] = client
            print('{}. {}'.format(counter, client))
            counter += 1
        return client_dic

    def _client_filter(self):
        clients = self.CAS.cas.clients
        filtred_clients = []
        for client in clients:
            if len(clients[client].connect) == 2:
                filtred_clients.append(client)
        return filtred_clients

    def _client_run(self, client_dic, mainprocess):
        choice = input('Select a client:\n>')
        client = client_dic.get(choice)
        if client:
            mainprocess(client)
        else:
            time.sleep(0.25)
            print("{} is NOT a valid choice".format(choice))
            time.sleep(1)
            self.client_connect_run()

    def _client_connect(self, client):
        clientobject = self.CAS.cas.clients[client]
        Constructor.construct(clientobject.connect[0], clientobject.connect[1],
                              self.username, self.pubKeyPath, self.privKeyPath,
                              self.password, clientobject.pubKeyPath,
                              clientobject.password)
        self._barAnimation()
        time.sleep(0.5)
        from Files import GUI
        GUI.main()
        time.sleep(1)
        print('You will redirect to dashboard')
        time.sleep(0.5)
        self.GUICleaner()
        self._dashboard()

# Client options

    def _client_options(self):
        while True:
            self._clientOptionsShow()
            self._clientOptionsRun()

    def _clientOptionsRun(self):
        choice = input('Enter a valid choice:\n>')
        action = self._clientOptionsRun_choices.get(choice)
        if action:
            action()
        else:
            print("{} is NOT a valid choice".format(choice))
            print()
            time.sleep(0.5)
            self._clientOptionsRun()

    def _clientOptionsShow(self):
        print(""">>>> Client Options [window] <<<<

Select a number from this options:
1. Register a client
2. Edit a client
3. Delete a client
4. Back to dashboard
5. Quit
    """)

    def _register_client(self):
        print('>>>> Client registering [window] <<<<')
        print()
        time.sleep(0.25)
        username = input("Enter client's name:\n>")
        pubKeyPath = input("Enter client's public key path:\n>")
        time.sleep(0.5)
        print('======================================================')
        print()
        time.sleep(0.5)
        print('If you want to connect to this client fill items below')
        print("if you don't want, then just press enter.")
        time.sleep(0.5)
        print()
        print('======================================================')
        time.sleep(0.5)
        ip = input("""Enter client's IPv4 address :
>""")
        if ip == '':
            ip = None
        port = input("""Enter client's port number:
>""")
        if port == '':
            port = None
        password = input("""
Enter client's password: (leave it empty if client doesn't support password)
>""")
        if password == '':
            password = None
        try:
            self.CAS.addClient(username, ip, port, pubKeyPath, password)
            time.sleep(0.5)
            print("""
=====================================
|+  Client registered successfuly!  +|
=====================================


            """)
            time.sleep(0.5)
            self._dashboard()
        except Auth.UsernameAlreadyExists:
            time.sleep(0.5)
            print("""
===============================
|+  Username already exists  +|
===============================


            """)
            time.sleep(0.5)
            self._register_client()
        except Auth.PathDoesNotExist:
            time.sleep(0.5)
            print("""
========================================
|+  Path to public key dosen't exist  +|
========================================


            """)
            time.sleep(0.5)
            self._dashboard()

    def _client_edit(self):
        print('>>>> Client editing [window] <<<<')
        print("""
Leave it empty if you don't want to change it, simply press ENTER""")
        time.sleep(0.25)
        self._client_tool(self.CAS.cas.clients, self._client_edit_process,
                          self._client_options)

    def _client_edit_process(self, username):
        name = input("Enter client's new name address:\n>")
        if name == '':
            name = None
        ip = input("Enter client's new IPv4 address:\n>")
        if ip == '':
            ip = None
        port = input("Enter client's new port number:\n>")
        if port == '':
            port = None
        pubKeyPath = input("Change client's new public key path:\n>")
        if pubKeyPath == '':
            pubKeyPath = None
        password = input("Change client's new password:\n>")
        if password == '':
            password = None

        self.CAS.editClient(username, name, ip, port, pubKeyPath, password)
        print("""
=============================================
|+  Client profile updated successfuly!  +|
=============================================


""")
        self._client_options()

    def _client_remove(self):
        print('>>>> Client deleting [window] <<<<')
        print()
        self._client_tool(self.CAS.cas.clients, self._client_remove_process,
                          self._client_options)

    def _client_remove_process(self, username):
        self.CAS.removeClient(username)
        time.sleep(0.5)
        print("""
===========================================
|+  Client profile deleted successfuly!  +|
===========================================


""")
        time.sleep(0.5)
        self._client_options()

    def _changePassword(self, counter=None):
        counter = counter
        if counter is None:
            counter = 0
        print('>>>> Change password [window] <<<<')
        time.sleep(0.5)
        old_password = input('Enter your old password:\n>')
        new_password = input('Enter your new password:\n>')
        if len(new_password) < 6:
            time.sleep(0.5)
            counter += 1
            print("""
==================================================
|+  New password must be at least 6 characters  +|
==================================================


            """)
            time.sleep(0.5)
            self._changePassword(counter)
        if old_password == new_password:
            time.sleep(0.5)
            counter += 1
            print("""
===================================================
|+  New password must be diffrent than old one!  +|
===================================================


            """)
            self._changePassword(counter)
        if counter > 4:
            print("""
==================================================
|+ Too many attempts! security protocol alert!  +|
==================================================


            """)
            time.sleep(0.5)
            self._signOut()
        try:
            self.CAS.changePassword(self.username, old_password, new_password)
        except Auth.NotLoggedInError:
            print('You are not logged in.')
            time.sleep(0.5)
            sys.exit()
        except Auth.InvalidPassword:
            counter += 1
            time.sleep(0.5)
            print("""
======================
|+  WRONG Password  +|
======================

            """)
            time.sleep(0.5)
            self._changePassword(counter)
        print('Password has been changed successfuly!')
        print('you have to sign in again')
        print()
        time.sleep(0.5)
        self._signOut()

    def _signOut(self, mode=None):
        if mode is not 'q':
            print('>>>> Sign out [window] <<<<')
            time.sleep(0.5)
        self.CAS.signOut(self.username)
        if mode is not 'q':
            print('Signing out ...')
            print()
            time.sleep(0.5)
        self.server1st = None
        self.server2nd = None
        self.clientlist = None
        self.username = None
        self.password = None
        self.pubKeyPath = None
        if mode is not 'q':
            self._run()

    def _quit(self, mode=None):
        if mode is not 'i':
            self._signOut('q')
            sys.exit()
        else:
            sys.exit()


class RepeatLogin(Exception):
    pass
