#pragma once
#include "protocol.h"
#include <sstream>
#include <string>
#include <vector>

constexpr auto CLIENT_INFO = "me.info";
constexpr auto SERVER_INFO = "transfer.info";

class CFileHandler;
class CSocketHandler;
class RSAPrivateWrapper;
class AESWrapper;

class CClientLogic
{
public:

	struct SClient
	{
		SClientID     id;
		std::string   username;
		std::string   filePath;
		SPrivateKey    privateKey;
		bool          privateKeySet = false;
		SAESKey AESKey;
		bool          AESKeySet = false;
	};

public:
	CClientLogic();
	virtual ~CClientLogic();
	CClientLogic(const CClientLogic& other) = delete;
	CClientLogic(CClientLogic&& other) noexcept = delete;
	CClientLogic& operator=(const CClientLogic& other) = delete;
	CClientLogic& operator=(CClientLogic&& other) noexcept = delete;

	// inline getters
	std::string getLastError() const { return _lastError.str(); }
	std::string getSelfUsername() const { return _client.username; }
	SClientID   getSelfClientID() const { return _client.id; }

	// client logic to be invoked by client menu.
	bool parseServerInfo();
	bool parseClientInfo();
	bool registerClient(const std::string& username);
	bool requestAESKey(const std::string& username);
	bool requestLogin(const std::string& username);
	bool requestSendFile(const std::string& username, uint8_t tryNumber);
	std::string getUsername();
	std::string getLastError();
	void handle4InvalidCRC(const std::string& fileName);
private:
	void clearLastError();
	bool storeClientInfo();
	void handleServerError();
	void handleGenericError();
	bool validateHeader(const SResponseHeader& header, const EResponseCode expectedCode);
	void setPrivateKey(const SPrivateKey& privateKey);
	void setAESKey(const SAESKey& AESKey);
	

	SClient              _client;
	std::stringstream    _lastError;
	std::unique_ptr<CFileHandler> _fileHandler;
	std::unique_ptr<CSocketHandler> _socketHandler;
	std::unique_ptr<RSAPrivateWrapper> _rsaDecryptor;
	std::unique_ptr<AESWrapper> _aesDecryptor;
};

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
void save_base64_to_file(const std::vector<unsigned char>& data);