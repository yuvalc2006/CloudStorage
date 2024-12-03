import os
import selectors
import socket
from file import *

import protocol
import client
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import time


class Server:
    PACKET_SIZE = protocol.MAX_PACKET_SIZE
    MAX_QUEUED_CONN = 5
    IS_BLOCKING = False

    def __init__(self, host, port):
        logging.basicConfig(format='[%(levelname)s - %(asctime)s]: %(message)s', level=logging.INFO, datefmt='%H:%M:%S')
        self.host = host
        self.port = port
        self.sel = selectors.DefaultSelector()
        self.lastErr = ""  # Last error description for debugging.
        # Mapping of request codes to corresponding handler methods.
        self.requestHandle = {
            protocol.ERequestCode.REQUEST_REGISTRATION.value: self.handle_registration_request,
            protocol.ERequestCode.REQUEST_PUBLIC_KEY.value: self.handle_public_key_request,
            protocol.ERequestCode.REQUEST_LOGIN.value: self.handle_login_request,
            protocol.ERequestCode.REQUEST_SEND_FILE.value: self.handle_send_file_request,
            protocol.ERequestCode.REQUEST_VALID_CRC.value: self.handle_valid_CRC_request,
            protocol.ERequestCode.REQUEST_INVALID_CRC.value: self.handle_invalid_CRC_request,
            protocol.ERequestCode.REQUEST_4_INVALID_CRC.value: self.handle4InvalidCRCRequest
        }

    def accept(self, sock, mask):
        """ Accept an incoming client connection and register it for reading. """
        conn, address = sock.accept()
        logging.info(f"Accepted connection from {address}.")
        conn.setblocking(Server.IS_BLOCKING)
        self.sel.register(conn, selectors.EVENT_READ, self.read)

    def read(self, conn, mask):
        """ Read data from the client and handle the request. """
        logging.info("A client has connected and sent data.")
        data = conn.recv(Server.PACKET_SIZE)
        if data:
            request_header = protocol.RequestHeader()
            fail = False
            if not request_header.unpack(data):
                logging.error("Failed to parse the request header!")
                fail = True
            elif request_header.code in self.requestHandle:
                try:
                    fail = not self.requestHandle[request_header.code](conn, data)
                except Exception as e:
                    logging.error(f"An unexpected error occurred: {e}")
                    fail = True
            else:
                logging.error("Received code illegal!")
                fail = True
            if fail:
                logging.error("Request failed. Sending error response.")
                responseHeader = protocol.ResponseHeader("RESPONSE_ERROR")
                self.write(conn, responseHeader.pack())
        else:
            logging.info("No data received from client.")
        self.sel.unregister(conn)
        conn.close()
        logging.info("Closed connection to client.")

    def write(self, conn, data):
        """ Send a response back to the client. """
        size = len(data)
        sent = 0
        logging.info(f"Sending {size} bytes of data to client.")
        try:
            conn.send(data)
        except Exception as e:
            logging.error(f"Failed to send data to client: {e}")
            return False
        logging.info("Response sent successfully.")
        return True

    def start(self):
        """ Start the server and listen for incoming connections. Main loop for handling events. """
        try:
            sock = socket.socket()
            sock.bind((self.host, self.port))
            sock.listen(Server.MAX_QUEUED_CONN)
            sock.setblocking(Server.IS_BLOCKING)
            self.sel.register(sock, selectors.EVENT_READ, self.accept)
            logging.info(f"Server started and listening on port {self.port}.")
        except Exception as e:
            self.lastErr = str(e)
            logging.error(f"Failed to start server: {e}")
            return False
        while True:
            try:
                events = self.sel.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)
            except Exception as e:
                logging.exception(f"Exception in server main loop: {e}")

    def handle_registration_request(self, conn, data):
        """ Handle new user registration. Validate and add to client database. """
        request = protocol.RegistrationRequest()
        fail = False
        if not request.unpack(data):
            logging.error("Registration Request: Failed to parse request.")
            fail = True
        try:
            if not request.name.isalnum():
                logging.info(f"Registration Request: Invalid username '{request.name}'.")
                fail = True
            if request.name in client.names:
                logging.info(f"Registration Request: Username '{request.name}' is already taken.")
                fail = True
        except Exception as e:
            logging.error(f"Registration Request: {e}")
            fail = True

        response = protocol.RegistrationFailureResponse() if fail else protocol.RegistrationSuccessResponse()
        if not fail:
            logging.info(f"User '{request.name}' registered successfully.")
            user = client.Client(request.name)
            return self.write(conn, response.pack(user.clientID))
        else:
            logging.info(f"User '{request.name}' failed registration.")
            return self.write(conn, response.pack())

    def handle_public_key_request(self, conn, data):
        """ Respond with the public key of the requested user. """
        request = protocol.SendPublicKeyRequest()
        if not request.unpack(data):
            logging.error("PublicKey Request: Failed to parse request header.")
            return False
        if request.header.clientID in client.clients:
            user = client.clients[request.header.clientID]
            user.public_key = request.public_key
        else:
            logging.error(f"PublicKey Request: User with ID {request.header.clientID} not found.")
            return False

        RSA_public_key = request.public_key
        AES_key = get_random_bytes(protocol.AES_KEY_SIZE)
        user.AES_key = AES_key
        encrypted_aes_key = self.encrypt_aes_key_with_rsa(AES_key, RSA_public_key)
        response = protocol.SendPublicKeyResponse()
        logging.info(f"PublicKey Request: Successfully responded to client ID {request.header.clientID}.")
        return self.write(conn, response.pack(request.header.clientID, encrypted_aes_key))

    def handle_login_request(self, conn, data):
        """ Handle user login request. Validate credentials and respond accordingly. """
        request = protocol.LoginRequest()
        fail = False
        if not request.unpack(data):
            logging.error("Login Request: Failed to parse request.")
            return False
        if request.header.clientID not in client.clients:
            logging.error(f"Login Request: User ID {request.header.clientID} not found.")
            fail = True
        user = client.clients.get(request.header.clientID)
        if not user.public_key:
            logging.error(f"Login Request: User {request.header.clientID} has no public key.")
            fail = True

        if fail:
            response = protocol.LoginFailResponse()
            logging.info(f"Login Request: Failed for client ID {request.header.clientID}.")
            return self.write(conn, response.pack(request.header.clientID))

        RSA_public_key = user.public_key
        AES_key = get_random_bytes(32)
        user.AES_key = AES_key
        encrypted_aes_key = self.encrypt_aes_key_with_rsa(AES_key, RSA_public_key)
        response = protocol.LoginSuccessResponse()
        logging.info(f"Login Request: Success for client ID {request.header.clientID}.")
        return self.write(conn, response.pack(request.header.clientID, encrypted_aes_key))

    def handle_send_file_request(self, conn, data):
        """Handle file sending request. Receive and decrypt file contents."""
        request = protocol.SendFileRequest()

        # Unpack request and validate
        if not request.unpack(data):
            logging.error("SendFile Request: Failed to parse request header.")
            return False
        if request.header.clientID not in client.clients:
            logging.error(f"SendFile Request: User ID {request.header.clientID} not found.")
            return False

        user = client.clients[request.header.clientID]

        file_name = request.file_name
        encrypted_content = request.message_content
        file_path = request.header.clientID + '\\' + file_name
        packets_received = request.packet_number
        total_packets = request.total_packets
        orig_file_size = request.orig_file_size
        content_size = request.content_size

        f = user.receive_file_packet(file_name, file_path, packets_received, total_packets, encrypted_content, orig_file_size, content_size)

        if packets_received == 1:
            user.add_file(file_name, f)

        if total_packets == packets_received:
            logging.info(f"file {file_name} received, sending CRC.")
            response = protocol.FileReceivedResponse()
            time.sleep(0.5)
            return self.write(conn,
                              response.pack(request.header.clientID, f.content_size, file_name, f.calculate_checksum()))
        return True

    def handle_valid_CRC_request(self, conn, data):
        """ Handle request to confirm a valid CRC (Cyclic Redundancy Check) for a received packet. """
        request = protocol.ValidCRCRequest()
        if not request.unpack(data):
            logging.error("ValidCRC Request: Failed to parse request header!")
            return False

        if request.header.clientID in client.clients:
            user = client.clients[request.header.clientID]
        else:
            logging.error(f"ValidCRC Request: User ID {request.header.clientID} not found!")
            return False

        f = user.files[request.file_name]
        f.CRC_valid = True
        logging.info(f"ValidCRC Request: '{request.file_name}' marked as valid.")

        response = protocol.ConfirmMessageResponse()
        return self.write(conn, response.pack(request.header.clientID))

    def handle_invalid_CRC_request(self, conn, data):
        """ Handle request indicating an invalid CRC for a received packet. """
        request = protocol.InvalidCRCRequest()
        if not request.unpack(data):
            logging.error("InvalidCRC Request: Failed to parse request header!")
            return False

        if request.header.clientID in client.clients:
            user = client.clients[request.header.clientID]
        else:
            logging.error(f"InvalidCRC Request: User ID {request.header.clientID} not found!")
            return False
        try:
            user.delete_file(request.file_name)
            logging.info(f"Invalid4CRC Request: File '{request.file_name}' deleted after 4 invalid CRCs.")
        except FileNotFoundError:
            logging.error(f"Invalid4CRC Request: File '{request.file_name}' not found during deletion.")

        return True

    def handle4InvalidCRCRequest(self, conn, data):
        """ Handle request indicating four consecutive invalid CRCs for a file. """
        request = protocol.Invalid4CRCRequest()
        if not request.unpack(data):
            logging.error("Invalid4CRC Request: Failed to parse request header!")
            return False

        if request.header.clientID in client.clients:
            user = client.clients[request.header.clientID]
        else:
            logging.error(f"Invalid4CRC Request: User ID {request.header.clientID} not found!")
            return False

        # Remove the file due to too many CRC errors.
        try:
            user.delete_file(request.file_name)
            logging.info(f"Invalid4CRC Request: File '{request.file_name}' deleted after 4 invalid CRCs.")
        except FileNotFoundError:
            logging.error(f"Invalid4CRC Request: File '{request.file_name}' not found during deletion.")

        response = protocol.ConfirmMessageResponse()
        return self.write(conn, response.pack(request.file_name))

    def encrypt_aes_key_with_rsa(self, aes_key, rsa_public_key):
        """ Encrypt the AES key using the RSA public key and return the encrypted key. """
        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        return encrypted_aes_key
