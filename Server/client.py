import logging
import os
import random
from protocol import CLIENTID_SIZE
from file import File

clients = {}
names = set()


def generate_random_id(size):
    # Randomly select 'size' characters from the ASCII characters
    random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for _ in range(size))
    return random_string


def create_dir(clientID):
    if os.path.exists(clientID):
        print(f"directory {clientID} already exists, pick a different name.")
        return False
    os.mkdir(clientID)


class Client:
    public_key = None
    AES_key = None

    def __init__(self, name):
        self.name = name
        self.clientID = generate_random_id(CLIENTID_SIZE)
        while self.clientID in clients:
            self.clientID = generate_random_id(CLIENTID_SIZE)
        clients[self.clientID] = self
        names.add(name)
        self.files = {}
        os.mkdir(self.clientID)

    def add_file(self, file_name, file):
        self.files[file_name] = file

    def receive_file_packet(self, file_name, path, packet_number, total_packets, content, orig_file_size, content_size):
        if file_name not in self.files:
            f = File(file_name, path, packet_number, total_packets, content, self.AES_key, orig_file_size, content_size)
            self.files[file_name] = f
        else:
            f = self.files[file_name]
            f.receive_packet(packet_number, total_packets, content, self.AES_key, orig_file_size, content_size)
        return f

    def delete_file(self, file_name):
        file_path = self.clientID + '\\' + file_name
        try:
            os.remove(file_path)
            logging.info(f"File '{file_path}' has been deleted.")
            del self.files[file_name]

        except FileNotFoundError:
            print(f"File '{file_path}' not found.")
        except PermissionError:
            print(f"Permission denied: Cannot delete '{file_path}'.")
        except Exception as e:
            print(f"An error occurred: {e}")
