#ifndef CFILEHANDLER_H
#define CFILEHANDLER_H

#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>

class CFileHandler {
public:
    // Constructors and Destructor
    CFileHandler();
    CFileHandler(const std::string& filename);
    ~CFileHandler();

    // File Operations
    size_t open(const std::string& filepath, bool write = false);
    void close();
    bool read(uint8_t* const dest, const size_t bytes) const;
    bool write(const uint8_t* const src, const size_t bytes) const;
    bool readLine(std::string& line) const;
    bool writeLine(const std::string& line) const;
    bool remove(const std::string& filePath) const;

    // Reading and Writing in One Go
    bool readAtOnce(const std::string& filepath, uint8_t*& file, size_t& bytes);
    bool writeAtOnce(const std::string& filepath, const std::string& data);

    // CRC Calculation
    unsigned long computeCRC();

    // Utilities
    size_t size() const;
    std::string getTempFolder() const;

private:
    // Internal Functions
    unsigned long memcrc(const char* buffer, size_t n);

    // Private Members
    std::unique_ptr<std::fstream> _fileStream;
    bool _open;
    std::string filename;
};

#endif // CFILEHANDLER_H
