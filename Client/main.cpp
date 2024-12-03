#include "CClientLogic.h"
#include <iostream>
#include <boost/algorithm/string/trim.hpp>
#include <string>
#include <iomanip>
#include <filesystem>

void clientStop(const std::string& error)
{
	std::cout << "Fatal Error: " << error << std::endl << "Client will stop." << std::endl;
	exit(1);
}

int main(int argc, char* argv[])
{
	CClientLogic clientLogic = CClientLogic();
	uint8_t tryNumber = 1;
	bool fail = false;


	if (!clientLogic.parseServerInfo()) {
		clientStop(clientLogic.getLastError());
		fail = true;
	}

	int index = 0;

	if (std::filesystem::exists(CLIENT_INFO)) {
		while (tryNumber < 4) {
			if (index == 0) {
				if (!clientLogic.parseClientInfo()) {
					clientStop(clientLogic.getLastError());
					fail = true;
				}
				else {
					index++;
					std::cout << "parsed client content.\n";
				}
			}
			
			if (index == 1) {
				if (!clientLogic.requestLogin(clientLogic.getUsername())) {
					clientStop(clientLogic.getLastError());
					fail = true;
				}
				else {
					index++;
					std::cout << "relogged into server.\n";
				}
			}
			
			if (index == 2) {
				if (!clientLogic.requestSendFile(clientLogic.getUsername(), tryNumber)) {
					std::cout << "Fatal Error: " << clientLogic.getLastError() << std::endl << "Client will stop." << std::endl;
					std::cout << "Problem sending file.\n";
					fail = true;
				}
				else {
					std::cout << "file sent and confirmed.\n";
					break;
				}
				
			}
			tryNumber++;
		}
	}

	else {
		while (tryNumber < 4) {
			if (index == 0) {
				if (!clientLogic.registerClient(clientLogic.getUsername())) {
					clientStop(clientLogic.getLastError());
					fail = true;
				}
				else {
					index++;
					std::cout << "registered to server.\n";
				}
			}

			if (index == 1) {
				if (!clientLogic.requestAESKey(clientLogic.getUsername())) {
					clientStop(clientLogic.getLastError());
					fail = true;
				}
				else {
					index++;
					std::cout << "completed key exchange.\n";
				}
				
			}

			if (index == 2) {
				if (!clientLogic.requestSendFile(clientLogic.getUsername(), tryNumber)) {
					std::cout << "Fatal Error: " << clientLogic.getLastError() << std::endl << "Client will stop." << std::endl;
					std::cout << "Problem sending file.\n";
					fail = true;
				}
				else {
					std::cout << "file sent and confirmed.\n";
					break;
				}
			}
			tryNumber++;
		}
	}
	if (tryNumber > 3 && index == 2) {
		//sends "invalid crc 4 times"
		clientLogic.requestSendFile(clientLogic.getUsername(), tryNumber);
	}

	return 0;
}
