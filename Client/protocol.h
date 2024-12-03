#pragma once
#include <cstdint>
#include <memory>

enum { DEF_VAL = 0 };  // Default value used to initialize protocol structures.

// Common types
typedef uint8_t  version_t;
typedef uint16_t code_t;
typedef uint32_t payloadSize_t;
typedef uint32_t contentSize_t;
typedef uint32_t origFileSize_t;
typedef uint16_t packetNumber_t;
typedef uint16_t totalPackets_t;
typedef uint32_t cksum_t;

// Constants. All sizes are in BYTES.
constexpr version_t CLIENT_VERSION = 3;
constexpr size_t    CLIENT_ID_SIZE = 16;
constexpr size_t    CODE_SIZE = 2;
constexpr size_t    VERSION_SIZE = 1;
constexpr size_t    CLIENT_NAME_SIZE = 255;
constexpr size_t    FILE_NAME_SIZE = 255;
constexpr size_t    FILE_TEXT_MAX = 500000;
constexpr size_t    MESSAGE_CONTENT_MAX = 10000;
constexpr size_t    FILE_PATH_SIZE = 255;
constexpr size_t    PUBLIC_KEY_SIZE = 160;
constexpr size_t    PRIVATE_KEY_SIZE = 160;
constexpr size_t    AES_KEY_SIZE = 32;
constexpr size_t    AES_ENCRYPTED_KEY_SIZE = 128;
constexpr size_t    REQUEST_OPTIONS = 7;
constexpr size_t    RESPONSE_OPTIONS = 8;
constexpr size_t    REQUEST_HEADER_SIZE = 23;
constexpr size_t    RESPONSE_HEADER_SIZE = 7;

enum ERequestCode
{
	REQUEST_REGISTRATION = 825,
	REQUEST_PUBLIC_KEY = 826,
	REQUEST_LOGIN = 827,
	REQUEST_SEND_FILE = 828,
	REQUEST_VALID_CRC = 900,
	REQUEST_INVALID_CRC = 901,
	REQUEST_4_INVALID_CRC = 902
};

enum EResponseCode
{
	RESPONSE_SUCCESS_REGISTRATION = 1600,
	RESPONSE_FAILURE_REGISTRATION = 1601,
	RESPONSE_PUBLIC_KEY = 1602,
	RESPONSE_FILE_SENT = 1603,
	RESPONSE_CONFIRM = 1604,
	RESPONSE_VALID_LOGIN = 1605,
	RESPONSE_INVALID_LOGIN = 1606,
	RESPONSE_ERROR = 1607    // payload invalid. payloadSize = 0.
};

#pragma pack(push, 1)

struct SClientID
{
	uint8_t uuid[CLIENT_ID_SIZE];
	SClientID() : uuid{ DEF_VAL } {}

	bool operator==(const SClientID& otherID) const {
		for (size_t i = 0; i < CLIENT_ID_SIZE; ++i)
			if (uuid[i] != otherID.uuid[i])
				return false;
		return true;
	}

	bool operator!=(const SClientID& otherID) const {
		return !(*this == otherID);
	}

};

struct SClientName
{
	uint8_t name[CLIENT_NAME_SIZE];  // DEF_VAL terminated.
	SClientName() : name{ '\0' } {}
};

struct SPublicKey
{
	uint8_t publicKey[PUBLIC_KEY_SIZE];
	SPublicKey() : publicKey{ DEF_VAL } {}
};

struct SPrivateKey
{
	uint8_t privateKey[PRIVATE_KEY_SIZE];
	SPrivateKey() : privateKey{ DEF_VAL } {}
};

struct SAESKey
{
	uint8_t AESKey[AES_KEY_SIZE];
	SAESKey() : AESKey{ DEF_VAL } {}

	bool operator==(const SAESKey& otherKey) const {
		for (size_t i = 0; i < AES_KEY_SIZE; ++i)
			if (AESKey[i] != otherKey.AESKey[i])
				return false;
		return true;
	}

	bool operator!=(const SAESKey& otherKey) const {
		return !(*this == otherKey);
	}
};

struct SAESEncryptedKey
{
	uint8_t AESEncryptedKey[AES_ENCRYPTED_KEY_SIZE];
	SAESEncryptedKey() : AESEncryptedKey{ DEF_VAL } {}
};

struct SRequestHeader
{
	SClientID       clientId;
	const version_t version;
	const code_t    code;
	payloadSize_t         payloadSize;
	SRequestHeader(const code_t reqCode) : version(CLIENT_VERSION), code(reqCode), payloadSize(DEF_VAL) {}
	SRequestHeader(const SClientID& id, const code_t reqCode) : clientId(id), version(CLIENT_VERSION), code(reqCode), payloadSize(DEF_VAL) {}
};

struct SResponseHeader
{
	version_t version;
	code_t    code;
	payloadSize_t   payloadSize;
	SResponseHeader() : version(DEF_VAL), code(DEF_VAL), payloadSize(DEF_VAL) {}
};

struct SRequestRegistration
{
	SRequestHeader header;
	struct
	{
		SClientName clientName;
	}payload;
	SRequestRegistration() : header(REQUEST_REGISTRATION) {}
};

struct SResponseSuccessRegistration
{
	SResponseHeader header;
	struct SPayloadHeader
	{
		SClientID clientID;
	}payload;
};

struct SResponseFailureRegistration
{
	SResponseHeader header;
};

struct SRequestPublicKey
{
	SRequestHeader header;
	struct SPayloadHeader
	{
		SClientName clientName;
		SPublicKey PublicKey;
	}payload;
	SRequestPublicKey(const SClientID& id) : header(id, REQUEST_PUBLIC_KEY) {}
};

struct SResponsePublicKey
{
	SResponseHeader header;
	struct
	{
		SClientID   clientId;
		SAESEncryptedKey  AESEncryptedKey;
	}payload;
};

struct SRequestSendFile {
	SRequestHeader header;

	// Payload structure to hold the data
	struct SPayloadHeader {
		contentSize_t contentSize;
		origFileSize_t origFileSize;
		packetNumber_t packetNumber;
		totalPackets_t totalPackets;
		char fileName[FILE_NAME_SIZE];
	} payload;

	// Constructor for SRequestSendFile
	SRequestSendFile(const SClientID& id)
		: header(id, REQUEST_SEND_FILE), payload{} {}
};

struct SResponseFileSent
{
	SResponseHeader header;
	struct SPayload
	{
		SClientID   clientId;
		contentSize_t contentSize;
		char fileName[FILE_NAME_SIZE] = { 0 };
		cksum_t cksum;
	}payload;
};

struct SRequestLogin
{
	SRequestHeader header;
	struct
	{
		SClientName clientName;
	}payload;
	SRequestLogin(const SClientID& id) : header(id, REQUEST_LOGIN) {}
};

struct SResponseValidLogin
{
	SResponseHeader header;
	struct
	{
		SClientID   clientId;
		SAESEncryptedKey  AESEncryptedKey;
	}payload;
};

struct SResponseInvalidLogin
{
	SResponseHeader header;
	struct
	{
		SClientID   clientId;
	}payload;
};

struct SRequestValidCRC
{
	SRequestHeader header;
	struct
	{
		char fileName[FILE_NAME_SIZE] = { 0 };
	}payload;
	SRequestValidCRC(const SClientID& id) : header(id, REQUEST_VALID_CRC) {}
};

struct SRequestInvalidCRC
{
	SRequestHeader header;
	struct
	{
		char fileName[FILE_NAME_SIZE] = { 0 };
	}payload;
	SRequestInvalidCRC(const SClientID& id) : header(id, REQUEST_INVALID_CRC) {}
};

struct SRequest4InvalidCRC
{
	SRequestHeader header;
	struct
	{
		char fileName[FILE_NAME_SIZE] = { 0 };
	}payload;
	SRequest4InvalidCRC(const SClientID& id) : header(id, REQUEST_4_INVALID_CRC) {}
};

struct SResponseConfirm
{
	SResponseHeader header;
	struct
	{
		SClientID   clientId;
	}payload;
};

struct SResponseError
{
	SResponseHeader header;
};

#pragma pack(pop)