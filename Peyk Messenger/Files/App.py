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
import sys
import errno
import time
from Files.Ciphers import FileCrypt
from Files.Constructor import Constructor
from Files.Server import ServerManager, SelfServerAdmin
from Files.Assets import BasicFunctions, AccountManager, Auth, Texts


class App:
    def __init__(self, system_info):
        self.file_path = os.path.dirname(os.path.abspath(__file__))
        self.log = os.path.join(self.file_path, 'Assets/System log.txt')
        self.info = system_info
        self.intro_choices = {
            "1": self._signup,
            "2": self._signin,
            "3": self._quit
        }
        self.dashboard_choices = {
            "1": self._connect_to_server,
            "2": self._register_server,
            "3": self._be_server_run,
            "4": self._connect_to_client,
            "5": self._client_options,
            "6": self._change_password,
            "7": self._sign_out,
            "8": self._quit
        }
        self._be_server_run_choices = {
            "1": self._start_be_server,
            "2": self._register_server,
            "3": self._server_edit,
            "4": self._server_remove,
            "5": self._dashboard,
            "6": self._quit
        }
        self._client_options_run_choices = {
            "1": self._register_client,
            "2": self._client_edit,
            "3": self._client_remove,
            "4": self._dashboard,
            "5": self._quit
        }

    @staticmethod
    def _intro_menu():
        print(Texts.intro_menu)

    def _run(self):
        while True:
            self._intro_menu()
            self._intro_choice_selector()

    def _intro_choice_selector(self):
        choice = input(Texts.enter_choice)
        action = self.intro_choices.get(choice)
        if action == self._quit:
            action('i')
        if action:
            action()
        else:
            print(Texts.not_valid.format(choice))
            print()
            time.sleep(0.5)
            self._intro_choice_selector()

    def _path_builder(self, username, mode):
        """ Creating directories for the group server """

        # Moving to /Data
        data_folder = os.path.join(self.file_path, 'Data')
        # Check if '/Data' directory already exits
        if os.path.isdir(data_folder):
            # Creating a directory for a user
            user_folder = os.path.join(data_folder, username)
            # Create directory
            if mode is 'a':
                try:
                    os.makedirs(user_folder)
                    # Check if directory created.
                    if os.path.isdir(user_folder):
                        # Joining all requires paths:
                        # Data/username/Servers >>> a folder to save server profiles
                        # Data/username/Clients >>> a folder to save client profiles
                        # Data/username/Keys >>> a folder to save user's private and public keys
                        name_list = ['Servers', 'Clients', 'Keys']
                        address_dict = dict()
                        for name in name_list:
                            address_dict[name] = os.path.join(user_folder, name)
                        for key in address_dict:
                            # If path already exists
                            if os.path.isdir(address_dict[key]):
                                # Go to next element
                                pass
                            # If path doesn't exist
                            else:
                                try:
                                    # Create directory
                                    os.makedirs(address_dict[key])
                                # Handling errors
                                except OSError as e:
                                    if e.errno != errno.EEXIST:
                                        raise
                        address_dict['User'] = user_folder
                        return address_dict
                # Handling errors
                except OSError as e:
                    if e.errno != errno.EEXIST:
                        raise
            elif mode is 'b':
                name_list = ['Servers', 'Clients', 'Keys']
                address_dict = dict()
                for name in name_list:
                    address_dict[name] = os.path.join(user_folder, name)
                address_dict['User'] = user_folder
                return address_dict
        # If path doesn't exist
        else:
            # Create directory
            try:
                os.makedirs(data_folder)
            # Handling errors
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise
            # Start again
            return self._path_builder(username, mode)

    def _signup(self):
        print(Texts.signup)
        print()
        time.sleep(0.5)
        if os.path.isfile(self.log):
            username_data = BasicFunctions.reader(self.log, 'p')
        else:
            username_data = dict()
        username = input(Texts.username)
        if username in username_data:
            print(Texts.signup_acc_exists)
            time.sleep(0.5)
            self._signup()
        time.sleep(0.25)
        password = input(Texts.password)
        try:
            path_dict = self._path_builder(username, 'a')
            cas = AccountManager.CAS(path_dict['User'], path_dict['Clients'], path_dict['Keys'])
            cas.signup(username, password)
            time.sleep(0.25)
            print(Texts.signup_successful)
            print()
            time.sleep(0.5)
            FileCrypt.file_crypt(self.info, path_dict['User'], password, 'e')
            username_data[username] = cas.cas.users[username].password
            BasicFunctions.writer(self.log, username_data, 'p')
            self._signin()
        except Auth.PasswordTooShort:
            time.sleep(0.5)
            print(Texts.pass_short)
            time.sleep(0.5)
            self._signup()

    def _signin(self):
        if os.path.isfile(self.log):
            username_data = BasicFunctions.reader(self.log, 'p')
        else:
            username_data = dict()
        if len(username_data) is not 0:
            print(Texts.login)
            print()
            time.sleep(0.25)
            username = input(Texts.username)
            if username in username_data:
                password = input(Texts.password)
                password_hash = BasicFunctions.hash_password(password, username)
                if password_hash == username_data[username]:
                    path_dict = self._path_builder(username, 'b')
                    FileCrypt.file_crypt(self.info, path_dict['User'], password, 'd')
                    cas = AccountManager.CAS(path_dict['User'], path_dict['Clients'], path_dict['Keys'])
                    if cas.login(username, password):
                        self.CAS = AccountManager.CAS(path_dict['User'], path_dict['Clients'], path_dict['Keys'])
                        self.server1st = ServerManager.server_init(path_dict['Servers'], 'Group Servers.txt')
                        self.server2nd = ServerManager.server_init(path_dict['Servers'], 'Self Servers.txt')
                        self.client_list = list(self.CAS.cas.clients.keys())
                        self.username = username
                        self.password = self.CAS.cas.users[username].password
                        self.pub_key_path = self.CAS.cas.users[username].pub_path
                        self.priv_key_path = self.CAS.cas.users[username].priv_path
                        time.sleep(0.25)
                        print(Texts.login_success)
                        time.sleep(0.25)
                        self._dashboard()
                    else:
                        time.sleep(0.5)
                        print(Texts.login_error)
                        time.sleep(0.5)
                        self._run()
                else:
                    time.sleep(0.5)
                    print(Texts.login_error)
                    time.sleep(0.5)
                    self._run()
            else:
                print(Texts.login_wrong_username)
                time.sleep(0.5)
                self._signin()
        else:
            time.sleep(0.25)
            print(Texts.login_no_acc)
            time.sleep(0.5)
            self._intro_choice_selector()

    def _dashboard(self):
        while True:
            self._dashboard_menu()
            self._dashboard_choice_selector()

    def _dashboard_menu(self):
        print(Texts.dashboard.format(self.username))

    def _dashboard_choice_selector(self):
        choice = input(Texts.enter_choice_dashboard)
        action = self.dashboard_choices.get(choice)
        if action:
            if action == self._register_server:
                action(self._dashboard, self.server1st)
            elif action == self._quit:
                action('s')
            else:
                time.sleep(0.5)
                action()
        else:
            print(Texts.not_valid.format(choice))
            print()
            time.sleep(0.5)
            self._dashboard_choice_selector()

    def _connect_to_server(self):  # TODO
        print(Texts.connect_server)
        print()
        database = self.server1st.server.serverU.servers
        if len(database) == 0:
            print("You didn't setup any server configuration before:")
            time.sleep(0.5)
            self._dashboard()
        else:
            print('Which server do you want to connect?')
            # TODO

    def _register_server(self, return_choice, database, mode):
        print(Texts.register_server)
        print()
        servername = input(Texts.server_name)
        if mode is 'p2p':
            client = input(Texts.server_client_name)
            if client == '':
                pass
            port = input(Texts.server_port)
            if port == '':
                time.sleep(0.25)
                print()
                print(Texts.server_port_error)
                print()
                time.sleep(1)
                self._register_server(return_choice, database, mode)
            password = input()
            if 0 < len(password) < 6:
                print(Texts.pass_short)
            if password == '':
                password = None
            try:
                database.server.addServer(servername, port, password)
                time.sleep(0.5)
                print(Texts.server_reg_success)
                time.sleep(0.5)
                return_choice()
            except Auth.UsernameAlreadyExists:
                time.sleep(0.5)
                print(Texts.sever_exists)
                time.sleep(0.5)
                self._register_server(return_choice, database, mode)
        elif mode is 'p2g':
            time.sleep(0.25)
            ip = input(Texts.server_ip)
            port = input(Texts.server_port)
            if port == '':
                time.sleep(0.25)
                print()
                print(Texts.server_port_error)
                print()
                time.sleep(1)
                self._register_server(return_choice, database, mode)
            password = input()
            if 0 < len(password) < 6:
                print(Texts.pass_short)
            if password == '':
                password = None
            try:
                database.server.addServer(servername, ip, port, password)
                time.sleep(0.5)
                print(Texts.server_reg_success)
                time.sleep(0.5)
                return_choice()
            except Auth.UsernameAlreadyExists:
                time.sleep(0.5)
                print(Texts.sever_exists)
                time.sleep(0.5)
                self._register_server(return_choice, database, mode)

    def _be_server_run(self):
        while True:
            self._be_server_run_show()
            self._be_server_choice_selector()

    @staticmethod
    def _be_server_run_show():
        print(Texts.be_server_menu)
        time.sleep(0.5)

    def _be_server_choice_selector(self):
        database = self.server2nd.server.servers
        choice = input(Texts.enter_choice)
        action = self._be_server_run_choices.get(choice)
        if action:
            if action is self._register_server:
                time.sleep(0.5)
                action(self._be_server_run, self.server2nd, 'p2p')
            elif action is self._quit:
                action('s')
            elif action is self._dashboard:
                time.sleep(0.5)
                action()
            else:
                time.sleep(0.5)
                action(database)
        else:
            print(Texts.not_valid.format(choice))
            print()
            time.sleep(0.5)
            self._be_server_choice_selector()

    def _start_be_server(self, database):
        def choice_to_connect(server_object):
            tag = server_object.tag
            if tag is 'public server':
                return server_object.connect, server_object.client
            elif tag is 'private server':
                return server_object.connect, server_object.client, server_object.password

        def server_to_client(client):
            try:
                client_object = self.CAS.cas.clients[client]
                return client_object.pubKeyPath
            except KeyError:
                print("The client Associated with this server doesn't exist!")
                print("You have to check to see if client name in server configured correctly.")
                time.sleep(0.5)
        time.sleep(0.25)
        if len(database.servers) is 0:
            print(Texts.server_no_profile)
            time.sleep(0.5)
            self._be_server_choice_selector()
        else:
            print(Texts.server_start)
            time.sleep(0.5)
            server_data = self._server_tool(database, choice_to_connect, 'connect')
            server = SelfServerAdmin.SSA(server_data, 10240, self.username, self.pubKeyPath, self.privKeyPath, self.password, self._serverToclient(server_data[1]))
            server._start_server()
            print('\n#>>> Initialization completed <<<#\n')
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

    def _server_to_client(self, client):
        try:
            client_object = self.CAS.cas.clients[client]
            return client_object.pubKeyPath
        except KeyError:
            print("The client Associated with this server doesn't exist!")
            print("You have to check to see if client name in server configured correctly.")
            time.sleep(0.5)
            self._be_server_run()

    @staticmethod
    def _server_tool(database, main_process, mode=None):
        def server_printer(d):
            d = d.servers
            s_dic = dict()
            counter = 1
            for server in d:
                s_dic[str(counter)] = server
                print('{}. {}'.format(counter, server))
                counter += 1
            return s_dic

        def server_choice(d, s_d, m_p, m=None):
            choice = input('Enter a valid choice from server list:\n>')
            server = s_d.get(choice)
            if server:
                if mode is 'connect':
                    d = d.servers
                    server_object = d[server]
                    return m_p(server_object)
                else:
                    m_p(database, server)
            else:
                print("{} is NOT a valid choice".format(choice))
                print()
                time.sleep(0.5)
                server_choice(d, s_d, m_p, m)
        time.sleep(0.5)
        server_dic = server_printer(database)
        if mode == 'connect':
            return server_choice(database, server_dic, main_process, mode)
        else:
            server_choice(database, server_dic, main_process, mode)

    @staticmethod
    def _choice_to_connect(server_object):
        tag = server_object.tag
        if tag is 'public server':
            return server_object.connect, server_object.client
        elif tag is 'private server':
            return server_object.connect, server_object.client, server_object.password

    def _server_edit(self, database):
        self._server_tool(database, self._server_edit_process)

    def _server_edit_process(self, database, server):
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

        database.serverEdit(server, name, ip, port, password)
        time.sleep(0.5)
        print("""
===========================================
|+  Server profile updated successfuly!  +|
===========================================


            """)
        time.sleep(0.5)
        self._be_server_run()

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
                          self._dashboard_choice_selector)

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

    def _change_password(self, counter=None):
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
            self._change_password(counter)
        if old_password == new_password:
            time.sleep(0.5)
            counter += 1
            print("""
========================================================
|+  New password must be different than the old one!  +|
========================================================


            """)
            self._change_password(counter)
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
            self._change_password(counter)
        print('Password has been changed successfuly!')
        print('you have to sign in again')
        print()
        time.sleep(0.5)
        self._sign_out()

    def _sign_out(self, mode=None):
        if mode is not 'q':
            print('>>>> Sign out [window] <<<<')
            time.sleep(0.5)
            print('Signing out ...')
            print()
            time.sleep(0.5)
        self.CAS.signOut(self.username)
        self.server1st = None
        self.server2nd = None
        self.client_list = None
        self.username = None
        self.password = None
        self.pubKeyPath = None
        if mode is not 'q':
            self._run()

    def _quit(self, mode):
        if mode is 'i':
            sys.exit()
        elif mode is 's':
            self._sign_out('q')
            sys.exit()


class RepeatLogin(Exception):
    pass
