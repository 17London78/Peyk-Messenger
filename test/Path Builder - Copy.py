import os
import errno
def main():
    def path_builder(username, mode):
        file_path = os.path.dirname(os.path.abspath(__file__))
        # Moving to /Data
        data_folder = os.path.join(file_path, 'Data')
        user_folder = os.path.join(data_folder, username)
        # Create directory
        if mode is 'a':
            # Check if '/Data' directory already exits
            if os.path.isdir(data_folder):
                try:
                    os.makedirs(user_folder)
                # Handling errors
                except OSError as e:
                    if e.errno != errno.EEXIST:
                        raise  # TODO
                else:
                    # Check if directory created.
                    if os.path.isdir(user_folder):
                        # Joining all requires paths:
                        # Data/username/Servers >>> a folder to save server profiles
                        # Data/username/Clients >>> a folder to save client profiles
                        # Data/username/Keys >>> a folder to save user's private and public keys
                        name_list = ['Servers', 'Clients', 'Keys']
                        address_dict = {name: os.path.join(user_folder, name) for name in name_list}
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
                                        raise  # TODO
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
                        raise  # TODO
                # Start again
                else:
                    return path_builder(username, mode)
        elif mode is 'b':
            name_list = ['Servers', 'Clients', 'Keys']
            address_dict = {name: os.path.join(user_folder, name) for name in name_list}
            return address_dict
    print(path_builder('Mohammad', 'a'))
    print(path_builder('Mahdi', 'b'))

main()
