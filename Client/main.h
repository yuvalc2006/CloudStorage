#ifndef CLIENT_HANDLER_H
#define CLIENT_HANDLER_H

#include "CClientLogic.h"
#include <iostream>
#include <boost/algorithm/string/trim.hpp>
#include <string>
#include <iomanip>
#include <filesystem>

// Function to handle client stop on fatal error
void clientStop(const std::string& error);

// The main function for handling the client logic
int main(int argc, char* argv[]);

#endif // CLIENT_HANDLER_H