import logging

from Crypto.PublicKey import RSA
import struct
from enum import Enum

CLIENTID_SIZE = 16
VERSION_SIZE = 1
CODE_SIZE = 2
PAYLOAD_SIZE_SIZE = 4
HEADER_WITHOUT_CLIENTID_SIZE = VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_SIZE
SERVER_VERSION = 3
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
CONTENT_SIZE = 4
ORIG_FILE_SIZE = 4
PACKET_NUMBER_SIZE = 2
TOTAL_PACKETS = 2
FILE_NAME_SIZE = 255
MESSAGE_CONTENT_MAX = 10000
MAX_PACKET_SIZE = MESSAGE_CONTENT_MAX + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_SIZE + CLIENTID_SIZE + ORIG_FILE_SIZE + PACKET_NUMBER_SIZE + TOTAL_PACKETS + CONTENT_SIZE + FILE_NAME_SIZE
CKSUM_SIZE = 4
AES_KEY_SIZE = 32


# Request Codes
class ERequestCode(Enum):
    REQUEST_REGISTRATION = 825  # uuid ignored.
    REQUEST_PUBLIC_KEY = 826
    REQUEST_LOGIN = 827
    REQUEST_SEND_FILE = 828
    REQUEST_VALID_CRC = 900
    REQUEST_INVALID_CRC = 901
    REQUEST_4_INVALID_CRC = 902


# Responses Codes
class EResponseCode(Enum):
    RESPONSE_REGISTRATION_SUCCESS = 1600
    RESPONSE_REGISTRATION_FAILURE = 1601
    RESPONSE_RECEIVED_PUBLIC_SEND_AES = 1602
    RESPONSE_RECEIVED_FILE_WITH_CRC = 1603
    RESPONSE_CONFIRM_MESSAGE_RECEIVED = 1604
    RESPONSE_CONFIRM_LOGIN_SEND_AES = 1605
    RESPONSE_DENY_LOGIN = 1606
    RESPONSE_ERROR = 1607


class SetPayloadSizeForCodes(Enum):
    # REQUEST_REGISTRATION = NAME_SIZE  # uuid ignored.
    # REQUEST_PUBLIC_KEY = NAME_SIZE + PUBLIC_KEY_SIZE
    # REQUEST_LOGIN = NAME_SIZE
    # REQUEST_SEND_FILE = CONTENT_SIZE + ORIG_FILE_SIZE + PACKET_NUMBER + TOTAL_PACKETS + FILE_NAME_SIZE
    # REQUEST_VALID_CRC = FILE_NAME_SIZE
    # REQUEST_INVALID_CRC = FILE_NAME_SIZE
    # REQUEST_4_INVALID_CRC = FILE_NAME_SIZE
    RESPONSE_REGISTRATION_SUCCESS = CLIENTID_SIZE
    RESPONSE_REGISTRATION_FAILURE = 0
    RESPONSE_RECEIVED_PUBLIC_SEND_AES = CLIENTID_SIZE
    RESPONSE_RECEIVED_FILE_WITH_CRC = CLIENTID_SIZE + CONTENT_SIZE + FILE_NAME_SIZE + CKSUM_SIZE
    RESPONSE_CONFIRM_MESSAGE_RECEIVED = CLIENTID_SIZE
    RESPONSE_CONFIRM_LOGIN_SEND_AES = CLIENTID_SIZE
    RESPONSE_DENY_LOGIN = CLIENTID_SIZE
    RESPONSE_ERROR = 0


class RequestHeader:
    def __init__(self):
        self.clientID = b""
        self.SIZE = CLIENTID_SIZE + HEADER_WITHOUT_CLIENTID_SIZE
        self.version = None
        self.code = None
        self.payloadSize = None

    def unpack(self, data):
        """ Little Endian unpack Request Header """
        try:
            self.clientID = struct.unpack(f"<{CLIENTID_SIZE}s", data[:CLIENTID_SIZE])[0].decode('utf-8').strip('\x00')
            headerData = data[CLIENTID_SIZE:CLIENTID_SIZE + HEADER_WITHOUT_CLIENTID_SIZE]
            self.version, self.code, self.payloadSize = struct.unpack("<BHL", headerData)
            if not check_server_version(self.version):
                logging.error("Server version is invalid")
                self.clear()
                return False
            if self.payloadSize > MAX_PACKET_SIZE:
                logging.error("Packet received too large")
                self.clear()
            return True
        except:
            self.clear()  # reset values
            return False
    def clear(self):
        self.clientID = b""
        self.version = b""
        self.code = b""
        self.payloadSize = b""


class ResponseHeader:
    def __init__(self, code):
        self.version = SERVER_VERSION
        self.code = EResponseCode[code].value
        self.payloadSize = SetPayloadSizeForCodes[code].value

    def pack(self):
        """ Little Endian pack Response Header """
        try:
            return struct.pack("<BHL", self.version, self.code, self.payloadSize)
        except:
            return b""


class RegistrationRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and Registration data """
        if not self.header.unpack(data):
            return False
        try:
            # trim the byte array after the nul terminating character.
            nameData = data[self.header.SIZE:self.header.SIZE + NAME_SIZE]
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", nameData)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            self.name = b""
            self.publicKey = b""
            return False


class RegistrationSuccessResponse:
    def __init__(self):
        self.header = ResponseHeader("RESPONSE_REGISTRATION_SUCCESS")

    def pack(self, clientID):
        """ Little Endian pack Response Header and client ID """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENTID_SIZE}s", clientID.encode('utf-8'))
            return data
        except:
            return b""


class RegistrationFailureResponse:
    def __init__(self):
        self.header = ResponseHeader("RESPONSE_REGISTRATION_FAILURE")

    def pack(self):
        """ Little Endian pack Response Header and client ID """
        try:
            data = self.header.pack()
            return data
        except:
            return b""


class SendPublicKeyRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""
        self.public_key = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and client ID """
        if not self.header.unpack(data):
            return False
        try:
            nameData = data[self.header.SIZE:self.header.SIZE + NAME_SIZE]
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", nameData)[0].partition(b'\0')[0].decode('utf-8'))
            public_key_data = data[self.header.SIZE + NAME_SIZE:self.header.SIZE + NAME_SIZE + PUBLIC_KEY_SIZE]
            self.public_key = RSA.import_key(public_key_data)
            return True
        except:
            self.clientID = b""
            self.name = b""
            self.public_key = b""
            return False


class SendPublicKeyResponse:
    def __init__(self):
        self.header = ResponseHeader("RESPONSE_RECEIVED_PUBLIC_SEND_AES")

    def pack(self, clientID, encrypted_AES_key):
        try:
            AES_key_len = len(encrypted_AES_key)
            self.header.payloadSize += AES_key_len
            data = self.header.pack()
            data += struct.pack(f"<{CLIENTID_SIZE}s", clientID.encode('utf-8'))
            data += struct.pack(f"<{AES_key_len}s", encrypted_AES_key)
            return data
        except:
            return b""


class LoginRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and client ID """
        if not self.header.unpack(data):
            return False
        try:
            nameData = data[self.header.SIZE:self.header.SIZE + NAME_SIZE]
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", nameData)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            self.name = b""
            return False


class LoginSuccessResponse:
    def __init__(self):
        self.header = ResponseHeader("RESPONSE_CONFIRM_LOGIN_SEND_AES")

    def pack(self, clientID, encrypted_AES_key):
        try:
            AES_key_len = len(encrypted_AES_key)
            self.header.payloadSize += AES_key_len
            data = self.header.pack()
            data += struct.pack(f"<{CLIENTID_SIZE}s", clientID.encode('utf-8'))
            data += struct.pack(f"<{AES_key_len}s", encrypted_AES_key)
            return data
        except:
            return b""


class LoginFailResponse:
    def __init__(self):
        self.header = ResponseHeader("RESPONSE_DENY_LOGIN")

    def pack(self, clientID):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENTID_SIZE}s", clientID.encode('utf-8'))
            return data
        except:
            return b""


class SendFileRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.content_size = b""
        self.orig_file_size = b""
        self.packet_number = b""
        self.total_packets = b""
        self.file_name = b""
        self.message_content = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and client ID """
        if not self.header.unpack(data):
            return False
        try:
            # read the content size
            last = self.header.SIZE
            contentSizeData = data[last:last + CONTENT_SIZE]
            self.content_size = struct.unpack("<I", contentSizeData)[0]
            # read the orig file size
            last += CONTENT_SIZE
            origFileSizeData = data[last:last + ORIG_FILE_SIZE]
            self.orig_file_size = struct.unpack("<I", origFileSizeData)[0]
            # read the packet number
            last += ORIG_FILE_SIZE
            packetNumberData = data[last:last + PACKET_NUMBER_SIZE]
            self.packet_number = struct.unpack("<H", packetNumberData)[0]
            # read the total packets
            last += PACKET_NUMBER_SIZE
            totalPacketsData = data[last:last + TOTAL_PACKETS]
            self.total_packets = struct.unpack("<H", totalPacketsData)[0]
            # read the file name
            last += TOTAL_PACKETS
            fileNameData = data[last:last + FILE_NAME_SIZE]
            self.file_name = str(
                struct.unpack(f"<{FILE_NAME_SIZE}s", fileNameData)[0].partition(b'\0')[0].decode('utf-8'))
            last += FILE_NAME_SIZE
            # get the message's content
            message_content_len = self.header.payloadSize - CONTENT_SIZE - ORIG_FILE_SIZE - PACKET_NUMBER_SIZE - TOTAL_PACKETS - FILE_NAME_SIZE
            messagecontestData = data[last:last + message_content_len]
            self.message_content = struct.unpack(f"<{message_content_len}s", messagecontestData)[0]
            return True
        except Exception as e:
            logging.error(f"Failed to unpack packet \"send file\" : {e}")
            self.clear()
            return False

    def clear(self):
        self.content_size = b""
        self.orig_file_size = b""
        self.packet_number = b""
        self.total_packets = b""
        self.file_name = b""
        self.message_content = b""


class FileReceivedResponse:
    def __init__(self):
        self.header = ResponseHeader("RESPONSE_RECEIVED_FILE_WITH_CRC")

    def pack(self, clientID, content_size, file_name, cksum):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENTID_SIZE}s", clientID.encode('utf-8'))
            data += struct.pack("<I", content_size)
            data += struct.pack(f"<{FILE_NAME_SIZE}s", file_name.encode('utf-8'))
            data += struct.pack("<I", cksum)
            return data
        except:
            return b""


class ValidCRCRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.file_name = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and client ID """
        if not self.header.unpack(data):
            return False
        try:
            fileNameData = data[self.header.SIZE:self.header.SIZE + FILE_NAME_SIZE]
            self.file_name = str(struct.unpack(f"<{NAME_SIZE}s", fileNameData)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            self.file_name = b""
            return False


class ConfirmMessageResponse:
    def __init__(self):
        self.header = ResponseHeader("RESPONSE_CONFIRM_MESSAGE_RECEIVED")

    def pack(self, clientID):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENTID_SIZE}s", clientID.encode('utf-8'))
            return data
        except:
            return b""


class InvalidCRCRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.file_name = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and client ID """
        if not self.header.unpack(data):
            return False
        try:
            fileNameData = data[self.header.SIZE:self.header.SIZE + FILE_NAME_SIZE]
            self.file_name = str(struct.unpack(f"<{NAME_SIZE}s", fileNameData)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            self.file_name = b""
            return False


class Invalid4CRCRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.file_name = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and client ID """
        if not self.header.unpack(data):
            return False
        try:
            fileNameData = data[self.header.SIZE:self.header.SIZE + FILE_NAME_SIZE]
            self.file_name = str(struct.unpack(f"<{NAME_SIZE}s", fileNameData)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            self.file_name = b""
            return False


def check_server_version(version):
    if version != SERVER_VERSION:
        return False
    return True
