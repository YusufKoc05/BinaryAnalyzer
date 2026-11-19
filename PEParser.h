#pragma once

#include "IParser.h"
#include "BinaryFile.h"

#include <string>
#include <vector>
#include <cstdint>

struct PESection
{
    std::string name;
    uint32_t virtualSize;
    uint32_t virtualAddress;
    uint32_t rawSize;
    uint32_t rawOffset;
    uint32_t characteristics;
    double entropy;
    bool isReadable;
    bool isWritable;
    bool isExecutable;
    bool isRWX;
};

struct PESecurityMitigations
{
    bool hasASLR = false;
    bool hasDEP = false;
    bool hasCFG = false;
    bool hasHighEntropyVA = false;
    bool hasSEH = true;
};

class PEParser : public IParser
{
private:
    BinaryFile& file;

    // Header Bilgileri
    uint32_t peOffset;
    uint16_t machine;
    std::string machineStr;
    uint16_t numberOfSections;
    uint32_t timeDateStamp;
    std::string compileTimeStr;
    uint16_t characteristics;
    bool is64Bit;

    // Optional Header
    uint64_t imageBase;
    uint32_t entryPoint;
    uint16_t subsystem;
    std::string subsystemStr;
    uint16_t dllCharacteristics;
    uint16_t optionalHeaderSize;

    PESecurityMitigations mitigations;
    std::vector<PESection> sections;
    std::vector<std::string> importedDlls;
    std::vector<std::string> importedFunctions;

    // Export ve İmza
    bool hasDigitalSignature = false;
    uint32_t signatureSize = 0;
    bool hasOverlay = false;
    size_t overlaySize = 0;
    std::string exportModuleName;
    std::vector<std::string> exportedFunctions;

    // Gelişmiş Malware & Reverse Engineering Göstergeleri
    std::string imphash;
    bool isDotNet = false;
    bool hasTls = false;
    uint32_t tlsCallbacksCount = 0;
    std::vector<uint64_t> tlsCallbackAddresses;
    std::string compilerDetected;
    std::string entryPointHexDump;
    std::string entryPointPrologue;

    // Yardımcı Dönüşümler
    uint32_t rvaToOffset(uint32_t rva) const;
    void parseImports(uint32_t importRva, uint32_t importSize);
    void parseExports(uint32_t exportRva, uint32_t exportSize);
    void parseTls(uint32_t tlsRva, uint32_t tlsSize);
    void detectCompiler();
    void disassembleEntryPoint();

public:
    explicit PEParser(BinaryFile& binaryFile);

    void parse() override;
    void printReport() const override;
    std::string getFormatName() const override { return "PE (Portable Executable)"; }

    const std::vector<PESection>& getSections() const { return sections; }
    const std::vector<std::string>& getImportedFunctions() const { return importedFunctions; }
    const std::vector<std::string>& getImportedDlls() const { return importedDlls; }
    const PESecurityMitigations& getMitigations() const { return mitigations; }
    bool getIs64Bit() const { return is64Bit; }
    uint32_t getEntryPoint() const { return entryPoint; }
    const std::string& getMachineStr() const { return machineStr; }
    const std::string& getSubsystemStr() const { return subsystemStr; }
    const std::string& getCompileTimeStr() const { return compileTimeStr; }
    bool getHasDigitalSignature() const { return hasDigitalSignature; }
    uint32_t getSignatureSize() const { return signatureSize; }
    bool getHasOverlay() const { return hasOverlay; }
    size_t getOverlaySize() const { return overlaySize; }
    const std::string& getExportModuleName() const { return exportModuleName; }
    const std::vector<std::string>& getExportedFunctions() const { return exportedFunctions; }

    const std::string& getImphash() const { return imphash; }
    bool getIsDotNet() const { return isDotNet; }
    bool getHasTls() const { return hasTls; }
    uint32_t getTlsCallbacksCount() const { return tlsCallbacksCount; }
    const std::vector<uint64_t>& getTlsCallbackAddresses() const { return tlsCallbackAddresses; }
    const std::string& getCompilerDetected() const { return compilerDetected; }
    const std::string& getEntryPointHexDump() const { return entryPointHexDump; }
    const std::string& getEntryPointPrologue() const { return entryPointPrologue; }
};
