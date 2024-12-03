#pragma once
#include <string>

class CStringer
{
public:
	static std::string encodeBase64(const std::string& str);
	static std::string encodeBase64(const uint8_t* data, size_t size);
	static std::string decodeBase64(const std::string& str);

	static std::string hex(const uint8_t* buffer, const size_t size);
	static std::string unhex(const std::string& hexString);

	static void trim(std::string& stringToTrim);

	static std::string getTimestamp();
};