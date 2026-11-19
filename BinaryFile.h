#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>

struct ExtractedString
{
    std::string value;
    size_t offset;
    bool isUnicode;
};

class BinaryFile
{
private:
    std::string filePath;
    std::vector<uint8_t> data;

public:
    explicit BinaryFile(const std::string& path);

    const std::string& getFilePath() const;
    size_t getSize() const;
    const std::vector<uint8_t>& getData() const;

    // Bounds-checked okuyucular
    uint8_t readByte(size_t offset) const;
    uint16_t readUInt16(size_t offset) const;
    uint32_t readUInt32(size_t offset) const;
    uint64_t readUInt64(size_t offset) const;
    std::string readAsciiString(size_t offset, size_t maxLength = 256) const;
    std::vector<uint8_t> readBytes(size_t offset, size_t count) const;

    // Shannon Entropi hesaplayıcı (0.0 - 8.0)
    static double calculateEntropy(const uint8_t* buffer, size_t length);
    double getOverallEntropy() const;

    // Kriptografik Parmak İzleri
    std::string getMD5() const;
    std::string getSHA1() const;
    std::string getSHA256() const;
    static std::string computeMD5String(const std::string& input);

    // String & IOC Çıkarıcı (ASCII & UTF-16LE)
    std::vector<ExtractedString> extractStrings(size_t minLength = 4, size_t maxCount = 2500) const;
};
