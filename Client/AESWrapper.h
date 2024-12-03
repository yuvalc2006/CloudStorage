#pragma once

#include <string>
#include "protocol.h"

class AESWrapper
{
private:
	unsigned char _key[AES_KEY_SIZE];
	AESWrapper(const AESWrapper& aes);
public:

	AESWrapper();
	AESWrapper(SAESKey AESKey);
	AESWrapper(const unsigned char* key, unsigned int size);
	~AESWrapper();

	const unsigned char* getKey() const;

	std::string encrypt(const char* plain, unsigned int length);
	std::string decrypt(const char* cipher, unsigned int length);
};