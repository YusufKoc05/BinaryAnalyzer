#pragma once

#include "IParser.h"
#include "BinaryFile.h"

#include <string>
#include <vector>
#include <cstdint>

struct ELFSection
{
    std::string name;
    uint32_t type;
    uint64_t flags;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    double entropy;
    bool isWritable;
    bool isExecutable;
    bool isAlloc;
    bool isRWX;
};

class ELFParser : public IParser
{
private:
    BinaryFile& file;

    bool is64Bit;
    bool isLittleEndian;
    uint8_t osAbi;
    std::string osAbiStr;
    uint16_t elfType;
    std::string elfTypeStr;
    uint16_t machine;
    std::string machineStr;
    uint64_t entryPoint;
    uint64_t shOffset;
    uint16_t shCount;
    uint16_t shStrIndex;
    bool executableStack; // PT_GNU_STACK executable?

    std::vector<ELFSection> sections;

public:
    explicit ELFParser(BinaryFile& binaryFile);

    void parse() override;
    void printReport() const override;
    std::string getFormatName() const override { return "ELF (Executable and Linkable Format)"; }

    const std::vector<ELFSection>& getSections() const { return sections; }
    bool getIs64Bit() const { return is64Bit; }
    uint64_t getEntryPoint() const { return entryPoint; }
    bool hasExecutableStack() const { return executableStack; }
    const std::string& getOsAbiStr() const { return osAbiStr; }
    const std::string& getElfTypeStr() const { return elfTypeStr; }
    const std::string& getMachineStr() const { return machineStr; }
};
