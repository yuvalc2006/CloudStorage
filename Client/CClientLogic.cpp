#include "CClientLogic.h"
#include "CStringer.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "CFileHandler.h"
#include "CSocketHandler.h"
#include <thread>
#include <chrono>

CClientLogic::CClientLogic()
	: _fileHandler(std::make_unique<CFileHandler>()),
	_socketHandler(std::make_unique<CSocketHandler>()),
	_rsaDecryptor(nullptr),
	_aesDecryptor(nullptr) {
}

CClientLogic::~CClientLogic() = default;

/**
 * Parse SERVER_INFO file for server address & port.
 */
bool CClientLogic::parseServerInfo()
{
	std::stringstream err;
	if (!_fileHandler->open(SERVER_INFO))
	{
		clearLastError();
		_lastError << "Couldn't open " << SERVER_INFO;
		return false;
	}
	std::string line;
	if (!_fileHandler->readLine(line))
	{
		clearLastError();
		_lastError << "Couldn't read " << SERVER_INFO;
		return false;
	}
	CStringer::trim(line);
	const auto pos = line.find(':');
	if (pos == std::string::npos)
	{
		clearLastError();
		_lastError << SERVER_INFO << " has invalid format! missing separator ':'";
		return false;
	}
	const auto address = line.substr(0, pos);
	const auto port = line.substr(pos + 1);
	if (!_socketHandler->setSocketInfo(address, port))
	{
		clearLastError();
		_lastError << SERVER_INFO << " has invalid IP address or port!";
		return false;
	}

	if (!_fileHandler->readLine(line))
	{
		clearLastError();
		_lastError << "Couldn't read username from " << CLIENT_INFO;
		return false;
	}
	CStringer::trim(line);
	if (line.length() >= CLIENT_NAME_SIZE)
	{
		clearLastError();
		_lastError << "Invalid username read from " << CLIENT_INFO;
		return false;
	}
	_client.username = line;

	if (!_fileHandler->readLine(line))
	{
		clearLastError();
		_lastError << "Couldn't read file path from " << CLIENT_INFO;
		return false;
	}
	CStringer::trim(line);
	if (line.length() >= FILE_PATH_SIZE)
	{
		clearLastError();
		_lastError << "Invalid file path read from " << CLIENT_INFO;
		return false;
	}
	_client.filePath = line;

	_fileHandler->close();
	return true;
}

/**
 * Parse CLIENT_INFO file.
 */
bool CClientLogic::parseClientInfo()
{
	std::string line;
	if (!_fileHandler->open(CLIENT_INFO, false))
	{
		clearLastError();
		_lastError << "Couldn't open " << CLIENT_INFO;
		return false;
	}

	// Read & Parse username
	if (!_fileHandler->readLine(line))
	{
		clearLastError();
		_lastError << "Couldn't read username from " << CLIENT_INFO;
		return false;
	}
	CStringer::trim(line);
	if (line.length() >= CLIENT_NAME_SIZE)
	{
		clearLastError();
		_lastError << "Invalid username read from " << CLIENT_INFO;
		return false;
	}
	_client.username = line;

	// Read & Parse Client's UUID.
	if (!_fileHandler->readLine(line))
	{
		clearLastError();
		_lastError << "Couldn't read client's UUID from " << CLIENT_INFO;
		return false;
	}

	line = CStringer::unhex(line);
	const char* unhexed = line.c_str();
	if (strlen(unhexed) != sizeof(_client.id.uuid))
	{
		memset(_client.id.uuid, 0, sizeof(_client.id.uuid));
		clearLastError();
		_lastError << "Couldn't parse client's UUID from " << CLIENT_INFO;
		return false;
	}
	memcpy(_client.id.uuid, unhexed, sizeof(_client.id.uuid));

	// Read & Parse Client's private key.
	std::string decodedKey;
	while (_fileHandler->readLine(line))
	{
		decodedKey.append(CStringer::decodeBase64(line));
	}
	if (decodedKey.empty())
	{
		clearLastError();
		_lastError << "Couldn't read client's private key from " << CLIENT_INFO;
		return false;
	}
	_fileHandler->close();

	try
	{
		_rsaDecryptor.reset();
		_rsaDecryptor = std::make_unique<RSAPrivateWrapper>(decodedKey);
	}
	catch (...)
	{
		clearLastError();
		_lastError << "Couldn't parse private key from " << CLIENT_INFO;
		return false;
	}
	//_fileHandler->close();
	return true;
}


/**
 * Reset _lastError StringStream: Empty string, clear errors flag and reset formatting.
 */
void CClientLogic::clearLastError()
{
	std::cout << _lastError.str();
	const std::stringstream clean;
	_lastError.str("");
	_lastError.clear();
	_lastError.copyfmt(clean);
}

/**
 * Store client info to CLIENT_INFO file.
 */

bool CClientLogic::storeClientInfo()
{
	// Open CLIENT_INFO file for writing
	if (!_fileHandler->open(CLIENT_INFO, true))
	{
		clearLastError();
		_lastError << "Couldn't open " << CLIENT_INFO;
		return false;
	}

	// Write username
	if (!_fileHandler->writeLine(_client.username))
	{
		clearLastError();
		_lastError << "Couldn't write username to " << CLIENT_INFO;
		return false;
	}
	// Write UUID
	std::string asciiUUID = CStringer::hex(_client.id.uuid, sizeof(_client.id.uuid));
	if (!_fileHandler->writeLine(asciiUUID))
	{
		clearLastError();
		_lastError << "Couldn't write UUID to " << CLIENT_INFO;
		return false;
	}

	// Write Base64 encoded private key to CLIENT_INFO
	const auto encodedKey = CStringer::encodeBase64(_rsaDecryptor->getPrivateKey());
	if (!_fileHandler->write(reinterpret_cast<const uint8_t*>(encodedKey.c_str()), encodedKey.size()))
	{
		clearLastError();
		_lastError << "Couldn't write client's private key to " << CLIENT_INFO;
		return false;
	}

	_fileHandler->close();  // Close CLIENT_INFO

	// Check if priv.key already exists using std::filesystem
	if (std::filesystem::exists("priv.key"))
	{
		clearLastError();
		_lastError << "priv.key already exists. Aborting write.";
		return false;
	}

	// Open priv.key using the same file handler
	if (!_fileHandler->open("priv.key", true))
	{
		clearLastError();
		_lastError << "Couldn't open priv.key for writing.";
		return false;
	}

	// Write the encoded key to priv.key
	if (!_fileHandler->write(reinterpret_cast<const uint8_t*>(encodedKey.c_str()), encodedKey.size()))
	{
		clearLastError();
		_lastError << "Couldn't write encoded key to priv.key.";
		_fileHandler->close();
		return false;
	}

	_fileHandler->close();  // Close priv.key

	return true;
}



void CClientLogic::handleServerError() {
	clearLastError();
	_lastError << "Server responded with an error";
}

void CClientLogic::handleGenericError() {
	clearLastError();
	_lastError << "Generic error response code received.";
}

/**
 * Validate SResponseHeader upon an expected EResponseCode.
 */
bool CClientLogic::validateHeader(const SResponseHeader& header, const EResponseCode expectedCode)
{
	if (header.code == RESPONSE_ERROR)
	{
		handleServerError();
		return false;
	}

	if (header.code != expectedCode)
	{
		clearLastError();
		_lastError << "Unexpected response code " << header.code << " received. Expected code was " << expectedCode;
		return false;
	}

	uint32_t expectedSize = DEF_VAL;
	switch (header.code)
	{
	case RESPONSE_SUCCESS_REGISTRATION:
	{
		expectedSize = sizeof(SResponseSuccessRegistration) - sizeof(SResponseHeader);
		break;
	}
	case RESPONSE_FAILURE_REGISTRATION:
	{
		expectedSize = sizeof(SResponseFailureRegistration) - sizeof(SResponseHeader);
		break;
	}
	case RESPONSE_PUBLIC_KEY:
	{
		expectedSize = sizeof(SResponsePublicKey) - sizeof(SResponseHeader);
		break;
	}
	case RESPONSE_FILE_SENT: {
		expectedSize = sizeof(SResponseFileSent) - sizeof(SResponseHeader);
		break;
	}
	case RESPONSE_CONFIRM: {
		expectedSize = sizeof(SResponseConfirm ) - sizeof(SResponseHeader);
		break;
	}
	case RESPONSE_VALID_LOGIN:
	{
		expectedSize = sizeof(SResponseValidLogin) - sizeof(SResponseHeader);
		break;
	}
	case RESPONSE_INVALID_LOGIN:
	{
		expectedSize = sizeof(SResponseInvalidLogin) - sizeof(SResponseHeader);
		break;
	}
	default:
	{
		return true;  // variable payload size. 
	}
	}

	if (header.payloadSize != expectedSize)
	{
		clearLastError();
		_lastError << "Unexpected payload size " << header.payloadSize << ". Expected size was " << expectedSize;
		return false;
	}

	return true;
}

std::string CClientLogic::getUsername() {
	return _client.username;
}

std::string CClientLogic::getLastError() {
	return _lastError.str();
}

void CClientLogic::setPrivateKey(const SPrivateKey& privateKey)
{
	_client.privateKey = privateKey;
	_client.privateKeySet = true;
}

/**
 * Store a client's symmetric key on RAM.
 */
void CClientLogic::setAESKey(const SAESKey& AESKey)
{

	_client.AESKey = AESKey;
	_client.AESKeySet = true;
}

void setName(SClientName& clientName, const std::string& username) {
	// Ensure we copy only up to CLIENT_NAME_SIZE - 1 to leave space for null terminator
	size_t length = username.copy(reinterpret_cast<char*>(clientName.name), CLIENT_NAME_SIZE - 1);
	clientName.name[length] = '\0'; // Null-terminate
}

/**
 * Register client via the server.
 */
bool CClientLogic::registerClient(const std::string& username)
{
	SRequestRegistration  request;
	uint8_t response[std::max(sizeof(SResponseSuccessRegistration), sizeof(SResponseSuccessRegistration))] = {0};

	if (username.length() >= CLIENT_NAME_SIZE)  // >= because of null termination.
	{
		clearLastError();
		_lastError << "Invalid username length!";
		return false;
	}
	for (auto ch : username)
	{
		if (!std::isalnum(ch))  // check that username is alphanumeric. [a-zA-Z0-9].
		{
			clearLastError();
			_lastError << "Invalid username! Username may only contain letters and numbers!";
			return false;
		}
	}

	// fill request data
	request.header.payloadSize = sizeof(request.payload);
	
	strcpy_s(reinterpret_cast<char*>(request.payload.clientName.name), CLIENT_NAME_SIZE, username.c_str());

	uint16_t code = _socketHandler->sendReceive(reinterpret_cast<const uint8_t* const>(&request), sizeof(request),
		reinterpret_cast<uint8_t* const>(response), std::max(sizeof(SResponseSuccessRegistration), sizeof(SResponseFailureRegistration)));

	if (!code)
	{
		clearLastError();
		_lastError << "Failed communicating with server on " << _socketHandler;
		return false;
	}

	if (code == RESPONSE_SUCCESS_REGISTRATION) {
		SResponseSuccessRegistration responseValid = SResponseSuccessRegistration();

		if (sizeof(SResponseSuccessRegistration) != sizeof(response))
		{
			std::cout << sizeof(SResponseSuccessRegistration) << " vs " << sizeof(response);
			clearLastError();
			_lastError << "Invalid response size from server!";
			return false;
		}

		memcpy(&responseValid, response, sizeof(SResponseSuccessRegistration));

		_client.id = responseValid.payload.clientID;

		_rsaDecryptor.reset();
		_rsaDecryptor = std::make_unique<RSAPrivateWrapper>();
		std::string privateKeyStr = _rsaDecryptor->getPrivateKey();
		SPrivateKey privateKeyStruct;
		size_t copySizePrivate = std::min(privateKeyStr.size(), sizeof(privateKeyStruct.privateKey));
		std::memcpy(privateKeyStruct.privateKey, privateKeyStr.data(), copySizePrivate);

		setPrivateKey(privateKeyStruct);

		if (!storeClientInfo())
		{
			clearLastError();
			_lastError << "Failed writing client info to " << CLIENT_INFO << ". Please register again with different username.";
			return false;
		}

		return true;
	}
		
	
	else if (code == RESPONSE_FAILURE_REGISTRATION) {
		clearLastError();
		_lastError << "Server refused registration, sent back code: " << code << ".";
		return false;
	}
	else if (code == RESPONSE_ERROR) {
		handleServerError();
		return false;
	}

	handleGenericError();
	return false;
}


/**
 * Invoke logic: request client public key from server.
 */
bool CClientLogic::requestAESKey(const std::string& username)
{
	SRequestPublicKey  request(_client.id);
	uint8_t response[sizeof(SResponsePublicKey)] = {0};

	setName(request.payload.clientName, username);

	std::string publicKeyStr = _rsaDecryptor->getPublicKey();

	SPublicKey publicKeyStruct;
	SPrivateKey privateKeyStruct = _client.privateKey;

	size_t copySizePublic = std::min(publicKeyStr.size(), sizeof(SPublicKey));
	std::memcpy(publicKeyStruct.publicKey, publicKeyStr.data(), copySizePublic);

	if (copySizePublic != PUBLIC_KEY_SIZE)
	{
		_lastError << "Invalid public key length!";
		return false;
	}

	request.header.payloadSize = sizeof(request.payload);
	strcpy_s(reinterpret_cast<char*>(request.payload.clientName.name), CLIENT_NAME_SIZE, username.c_str());
	memcpy_s(reinterpret_cast<char*>(request.payload.PublicKey.publicKey), PUBLIC_KEY_SIZE, publicKeyStruct.publicKey, PUBLIC_KEY_SIZE);

	uint16_t code = _socketHandler->sendReceive(reinterpret_cast<const uint8_t* const>(&request), sizeof(request),
		reinterpret_cast<uint8_t* const>(&response), sizeof(response));

	if (!code)
	{
		clearLastError();
		_lastError << "Failed communicating with server on " << _socketHandler;
		return false;
	}

	if (code == RESPONSE_PUBLIC_KEY) {
		SResponsePublicKey responseValid = SResponsePublicKey();
		if (sizeof(SResponsePublicKey) != sizeof(response))
		{
			clearLastError();
			_lastError << "Invalid response size from server!";
			return false;
		}

		memcpy(&responseValid, response, sizeof(SResponsePublicKey));
		
		if (request.header.clientId != responseValid.payload.clientId)
		{
			clearLastError();
			_lastError << "Unexpected clientID was received.";
			return false;
		}
		
		std::string decrypted = _rsaDecryptor->decrypt(responseValid.payload.AESEncryptedKey.AESEncryptedKey, AES_ENCRYPTED_KEY_SIZE);

		if (decrypted.length() != AES_KEY_SIZE) {
			clearLastError();
			_lastError << "AES key received has unexpected size.";
			return false;
		}

		SAESKey AESKey = SAESKey();
		memcpy(AESKey.AESKey, decrypted.data(), AES_KEY_SIZE);
		setAESKey(AESKey);
		if (!_client.privateKeySet) {
			setPrivateKey(privateKeyStruct);
		}

		return true;
	}
	else if (code == RESPONSE_ERROR) {
		handleServerError();
		return false;
	}

	handleGenericError();
	return false;
}

bool CClientLogic::requestLogin(const std::string& username)
{
	SRequestLogin  request(_client.id);
	uint8_t response[std::max(sizeof(SResponseValidLogin), sizeof(SResponseInvalidLogin))] = {0};

	if (username.length() >= CLIENT_NAME_SIZE)  // >= because of null termination.
	{
		clearLastError();
		_lastError << "Invalid username length!";
		return false;
	}
	for (auto ch : username)
	{
		if (!std::isalnum(ch))  // check that username is alphanumeric. [a-zA-Z0-9].
		{
			clearLastError();
			_lastError << "Invalid username! Username may only contain letters and numbers!";
			return false;
		}
	}

	// fill request data
	request.header.payloadSize = sizeof(request.payload);

	strcpy_s(reinterpret_cast<char*>(request.payload.clientName.name), CLIENT_NAME_SIZE, username.c_str());

	uint16_t code = _socketHandler->sendReceive(reinterpret_cast<const uint8_t* const>(&request), sizeof(request),
		reinterpret_cast<uint8_t* const>(response), sizeof(response));

	if (!code)
	{
		clearLastError();
		_lastError << "Failed communicating with server on " << _socketHandler;
		return false;
	}

	if (code == RESPONSE_VALID_LOGIN) {
		SResponseValidLogin responseValid = SResponseValidLogin();
		if (sizeof(SResponseValidLogin) != sizeof(response))
		{
			clearLastError();
			_lastError << "Invalid response size from server!";
			return false;
		}

		memcpy(&responseValid, response, sizeof(SResponseValidLogin));

		if (_client.id != responseValid.payload.clientId) {
			clearLastError();
			_lastError << "Id received is deifferent from the one stored";
			return false;
		}
		
		std::string decrypted = _rsaDecryptor->decrypt(responseValid.payload.AESEncryptedKey.AESEncryptedKey, AES_ENCRYPTED_KEY_SIZE);

		if (decrypted.length() != AES_KEY_SIZE) {
			clearLastError();
			_lastError << "AES key received has unexpected size.";
			return false;
		}

		SAESKey AESKey = SAESKey();
		memcpy(AESKey.AESKey, decrypted.data(), AES_KEY_SIZE);

		setAESKey(AESKey);

		return true;
	}
	
	else if (code == RESPONSE_INVALID_LOGIN) {
		clearLastError();
		_lastError << "Server refused login, sent back code: " << code << ".";
		return false;
	}
	
	else if (code == RESPONSE_ERROR) {
		handleServerError();
		return false;
	}

	handleGenericError();
	return false;
}

bool CClientLogic::requestSendFile(const std::string& username, uint8_t tryNumber) {
	std::string fileName = _client.filePath.substr(_client.filePath.find_last_of("/\\") + 1);
	if (tryNumber > 3) {
		handle4InvalidCRC(fileName);
		return true;
	}
		

	if (username.length() >= CLIENT_NAME_SIZE) {
		clearLastError();
		_lastError << "Invalid username length!";
		return false;
	}

	// Ensure username is alphanumeric
	for (const auto& ch : username) {
		if (!std::isalnum(ch)) {
			clearLastError();
			_lastError << "Invalid username! Only letters and numbers allowed.";
			return false;
		}
	}
	
	size_t fileSize = _fileHandler->open(_client.filePath, false);

	if (!fileSize) {
		clearLastError();
		_lastError << "Problem opening file: " << _client.filePath;
		return false;
	}

	if (fileSize > FILE_TEXT_MAX) {
		clearLastError();
		_lastError << "file too big: " << _client.filePath;
		return false;
	}

	uint8_t* buffer = new uint8_t[fileSize];

	if (!_fileHandler->readAtOnce(_client.filePath, buffer, fileSize)) {
		clearLastError();
		_lastError << "Problem reading file: " << _client.filePath;
		return false;
	}
	_fileHandler->close();

	// Calculate total packets needed
	size_t totalPackets = (fileSize + MESSAGE_CONTENT_MAX - 1) / MESSAGE_CONTENT_MAX;  // Round up

	// Prepare the request and fill the file name
	SRequestSendFile request(_client.id);
	strncpy_s(request.payload.fileName, FILE_NAME_SIZE, fileName.c_str(), FILE_NAME_SIZE - 1);
	
	_aesDecryptor.reset();
	_aesDecryptor = std::make_unique<AESWrapper>(_client.AESKey);
	std::string encryptedContent = _aesDecryptor->encrypt(reinterpret_cast<char*>(buffer), fileSize);
	uint32_t contentSize = encryptedContent.length();

	request.payload.contentSize = static_cast<contentSize_t>(contentSize);
	request.payload.origFileSize = static_cast<origFileSize_t>(fileSize);
	request.payload.totalPackets = static_cast<totalPackets_t>(totalPackets);

	size_t bytesRead = 0;
	size_t packetNumber = 1;
	size_t sendNow = 0;
	
	// Start the file transfer
	while (packetNumber <= totalPackets) {
		sendNow = (contentSize - bytesRead < MESSAGE_CONTENT_MAX) ? contentSize - bytesRead : MESSAGE_CONTENT_MAX;
		
		// Fill the payload for this packet
		request.payload.packetNumber = static_cast<packetNumber_t>(packetNumber);
		request.header.payloadSize = static_cast<payloadSize_t>(sizeof(request.payload) + sendNow);

		uint8_t* requestBuffer = (uint8_t*)malloc(sizeof(SRequestSendFile) + sendNow);
		memcpy(requestBuffer, &request, sizeof(SRequestSendFile));
		memcpy(requestBuffer + sizeof(SRequestSendFile), encryptedContent.c_str() + bytesRead, sendNow);

		if (!_socketHandler->connect())
		{
			clearLastError();
			_lastError << "Failed to connect to the server.";
			return false;
		}

		if (!_socketHandler->send(reinterpret_cast<const uint8_t*>(requestBuffer), sizeof(SRequestSendFile) + sendNow)) {
			clearLastError();
			_lastError << "Failed to send packet " << packetNumber << " to server.";
			_fileHandler->close();
			return false;
		}

		if (packetNumber != totalPackets)
			_socketHandler->close();

		++packetNumber;
		bytesRead += sendNow;

		free(requestBuffer);

		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}

	// Now, receive the server's response
	uint8_t responseBuffer[sizeof(SResponseFileSent)] = { 0 };

	uint16_t code = _socketHandler->receive(responseBuffer, sizeof(responseBuffer));

	if (!code) {
		clearLastError();
		_lastError << "Failed to receive server response after file transfer.";
		return false;
	}

	if (code == RESPONSE_ERROR) {
		handleServerError();
		return false;
	}
	if (code != RESPONSE_FILE_SENT) {
		handleGenericError();
		return false;
	}

	// Parse the server's response
	SResponseFileSent response;
	std::memcpy(&response, responseBuffer, sizeof(SResponseFileSent));

	bool fail = false;

	size_t fileSizeCRC = _fileHandler->open(_client.filePath, false);

	if (!fileSizeCRC) {
		clearLastError();
		_lastError << "problem opening file to calculate checksum.";
		return false;
	}

	uint32_t crc = _fileHandler->computeCRC();

	_fileHandler->close();

	if (!crc) {
		clearLastError();
		_lastError << "could not calculate checksum.";
		return false;
	}

	if (response.payload.cksum == crc) {
		if (std::strncmp(request.payload.fileName, response.payload.fileName, FILE_NAME_SIZE) != 0) {
			clearLastError();
			_lastError << "file name received doesn't match the 1 sent.";
			return false;
		}

		SRequestValidCRC newRequest = SRequestValidCRC(_client.id);
		uint8_t newResponse[sizeof(SResponseConfirm)] = {0};
		std::memcpy(newRequest.payload.fileName, request.payload.fileName, FILE_NAME_SIZE);
		newRequest.header.payloadSize = sizeof(newRequest.payload);

		uint16_t code = _socketHandler->sendReceive(reinterpret_cast<const uint8_t* const>(&newRequest), sizeof(newRequest),
			reinterpret_cast<uint8_t* const>(newResponse), sizeof(newResponse));

		if (!code) {
			clearLastError();
			_lastError << "Failed communicating with server on " << _socketHandler;
			fail = true;
		}

		else if (code == RESPONSE_ERROR) {
			handleServerError();
			fail = true;
		}

		else if (code != RESPONSE_CONFIRM) {
			handleGenericError();
			fail = true;
		}
	}

	else {
		SRequestInvalidCRC newRequest = SRequestInvalidCRC(_client.id);
		std::memcpy(newRequest.payload.fileName, request.payload.fileName, FILE_NAME_SIZE);

		if (!_socketHandler->send(reinterpret_cast<const uint8_t*>(&newRequest), sizeof(newRequest))) {
			clearLastError();
			_lastError << "Failed to send packet with code " << REQUEST_INVALID_CRC << " to server.";
			_fileHandler->close();
			fail = true;
		}
		_fileHandler->close();
		return false;
	}

	// File sent successfully
	_fileHandler->close();  // Close the file after sending all packets
	return !fail;
}

void CClientLogic::handle4InvalidCRC(const std::string& fileName) {
	SRequest4InvalidCRC newRequest = SRequest4InvalidCRC(_client.id);

	// Ensure the filename fits within the buffer, accounting for the null terminator.
	size_t copySize = std::min(fileName.size(), FILE_NAME_SIZE - 1);

	// Copy the data safely to the char array.
	std::memcpy(newRequest.payload.fileName, fileName.data(), copySize);

	// Null-terminate the string.
	newRequest.payload.fileName[copySize] = '\0';

	if (!_socketHandler->send(reinterpret_cast<const uint8_t*>(&newRequest), sizeof(newRequest))) {
		clearLastError();
		_lastError << "Failed to send packet with code " << REQUEST_4_INVALID_CRC << " to server.";
		return;
	}
}