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

signup = '>>>> Signup [window] <<<<'
login = '>>>> Login [window] <<<<'
connect_server = '>>>> Connect to a Server [window] <<<<'
register_server = '>>>> Server registering [window] <<<<'
username = 'Enter your username:\n>'
password = 'Enter your password:\n>'
server_name =  "Enter server's name:\n>"
server_ip = "Enter server's IPv4 address: \n>"
server_port = "Enter server's port number:\n>"
enter_choice_dashboard = 'Enter a valid choice from dashboard menu:\n>'
enter_choice = 'Enter a valid choice:\n>'
not_valid = '{} is not a valid choice!'
intro_menu = """
Welcome to Peyk Messenger v0.1 [BETA]

Select a number from this options:

1. signUp
2. signIn
3. Quit
"""
pass_short = """
====================================================
|+          Your password is TOO SHORT!           +|
|+  Your password must be at least 6 characters.  +|
====================================================
"""
signup_successful = """
========================================================
|+  Your account has been activated, log in please.  +|
========================================================
"""
Signup_user_exists = """
====================================
|+  The username isn't available.  +|
====================================
"""
signup_acc_exists = """
=========================================================================
|+  There is an account with this name, you can't register a new one!  +|
|+                    You have to choose another name! .               +|
=========================================================================
"""
login_success = """
====================================
|+  Login completed successfully.  +|
====================================
"""
login_wrong_username = """
==================================
|+  This username is not valid  +|
==================================
"""
login_error = """
===================================
|+  Wrong username or password.  +|
===================================
"""
login_already_in = """
=======================================
|+  This user is already logged in.  +|
=======================================
"""
login_no_acc = """
=================================================================
|+  There is not any accounts in the app , you can't sign in!  +|
|+              You have to SIGN UP first.                     +|
=================================================================
"""
dashboard = """
+++>>> Welcome to your dashboard dear {} <<<++

Select a number from this options:
1. Connect to a server
2. Register a server
3. Become a server
4. Connect to a client
5. Client options
6. Change password
7. Sign out
8. Quit
"""
server_password: "Enter server's password: (leave it empty if it's a public server) \n>"
server_port_error = 'You must enter a port number for server!'
server_client_name = "Enter Associated client's name:\n>"
be_server_menu = """
>>>> Become a Server [window] <<<<

Select a number from this options:
1. Start a server
2. Register a server
3. Edit a server
4. Delete a server
5. Back to dashboard
6. Quit
    """
server_reg_success = """
=====================================
|+ Server registered successfully! +|
=====================================
"""
server_exists = """
==================================
|+  Server name already exists  +|
==================================
"""
server_no_profile = 'There is not any server profile available'
server_start = 'Which server do you want to start?'
server_welcome = 'You are now connected to the server at {} on port {}.'
