import os
import errno
def main():
    def path_builder(username, mode):
        """ Creating directories for the group server """
        file_path = os.path.dirname(os.path.abspath(__file__))
        def path_list():
            name_list = ['Servers', 'Clients', 'Keys']
            address_dict = {name: os.path.join(user_folder, name) for name in name_list}
            address_dict['User'] = user_folder
            return address_dict

        def makedir_handle(folder):
            try:
                # Create directory
                os.makedirs(folder)
            # Handling errors
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise  # TODO
        # Moving to /Data
        data_folder = os.path.join(file_path, 'Data')
        user_folder = os.path.join(data_folder, username)
        # Create directory
        if mode is 'a':
            for i in [data_folder, user_folder]:
                # If path doesn't exist
                if not os.path.isdir(i):
                    # Create directory
                    makedir_handle(i)
            # Joining all requires paths:
            # Data/username/Servers >>> a folder to save server profiles
            # Data/username/Clients >>> a folder to save client profiles
            # Data/username/Keys >>> a folder to save user's private and public keys
            address = path_list()
            for key in address:
                # If path already exists
                if not os.path.isdir(address[key]):
                    # If path doesn't exist
                    makedir_handle(address[key])
            return address
        elif mode is 'b':
            return path_list()
    c = path_builder('Mohammad', 'a')
    print(c)

main()
