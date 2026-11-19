#pragma once

#include "BinaryFile.h"
#include "PEParser.h"
#include "ELFParser.h"
#include "MalwareAnalyzer.h"

#include <string>
#include <vector>
#include <map>
#include <memory>

struct AnalysisResult
{
    bool success = false;
    std::string errorMessage;

    // Temel Dosya Bilgileri
    std::string filePath;
    std::string fileName;
    size_t fileSize = 0;
    std::string formattedSize;
    // Kriptografik Hash Ailesi
    std::string md5;
    std::string sha1;
    std::string sha256;
    std::string imphash;
    double overallEntropy = 0.0;
    bool isPackedOrEncrypted = false;

    // Format & Mimari & Derleyici
    std::string formatName; // PE32, PE32+, ELF32, ELF64
    std::string architecture;
    std::string subsystem;
    std::string compileTime;
    std::string compilerDetected;
    uint64_t entryPoint = 0;
    bool is64Bit = false;

    // PE Güvenlik & İmza & Overlay & TLS & .NET
    PESecurityMitigations mitigations;
    bool hasDigitalSignature = false;
    uint32_t signatureSize = 0;
    bool hasOverlay = false;
    size_t overlaySize = 0;
    bool isDotNet = false;
    bool hasTls = false;
    uint32_t tlsCallbacksCount = 0;
    std::vector<uint64_t> tlsCallbackAddresses;
    std::string entryPointHexDump;
    std::string entryPointPrologue;

    // ELF Linux Kontrolleri
    bool elfExecutableStack = false;
    std::string elfOsAbi;

    // Bölümler
    std::vector<PESection> peSections;
    std::vector<ELFSection> elfSections;

    // Import & Export
    std::vector<std::string> importedDlls;
    std::vector<std::string> importedFunctions;
    std::string exportModuleName;
    std::vector<std::string> exportedFunctions;

    // Stringler & IOC (Indicators of Compromise)
    std::vector<ExtractedString> extractedStrings;
    std::vector<std::string> detectedIocUrls;
    std::vector<std::string> detectedIocIps;
    std::vector<std::string> detectedIocCommands;

    // Tehdit & Malware Bulguları
    int riskScore = 0;
    std::string riskLevel; // DUSUK, ORTA, YUKSEK, KRITIK
    std::vector<SuspiciousFinding> findings;
    std::map<std::string, std::vector<std::string>> categorizedDetections;

    // Raporlar
    std::string fullReportText;
    std::string generateHtmlReport() const;
    std::string generateJsonReport() const;
};

class AnalyzerEngine
{
public:
    static AnalysisResult analyze(const std::string& filePath);
};
