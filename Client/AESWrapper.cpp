#include "AESWrapper.h"

#include <modes.h>
#include <aes.h>
#include <filters.h>

#include <stdexcept>
#include <immintrin.h>

#include <iostream>
#include <fstream>
#include <string>

AESWrapper::AESWrapper() {
	// Initialize the key with zero bytes for safety.
	std::memset(_key, 0, AES_KEY_SIZE);
}

AESWrapper::AESWrapper(SAESKey AESKey) {
	memcpy_s(_key, AES_KEY_SIZE, AESKey.AESKey, sizeof(AESKey.AESKey));
}

AESWrapper::AESWrapper(const unsigned char* key, unsigned int length)
{
	memcpy_s(_key, AES_KEY_SIZE, key, length);
}

AESWrapper::~AESWrapper()
{
}

const unsigned char* AESWrapper::getKey() const
{
	return _key;
}

std::string AESWrapper::encrypt(const char* plain, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

	CryptoPP::AES::Encryption aesEncryption(_key, AES_KEY_SIZE);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	std::string cipher;
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
	stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
	stfEncryptor.MessageEnd();
	return cipher;
}


std::string AESWrapper::decrypt(const char* cipher, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

	CryptoPP::AES::Decryption aesDecryption(_key, AES_KEY_SIZE);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	std::string decrypted;
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
	stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
	stfDecryptor.MessageEnd();

	return decrypted;
}
