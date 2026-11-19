#include "PEParser.h"
#include "MalwareAnalyzer.h"

#include <iostream>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace
{
    std::string formatTimestamp(uint32_t timestamp)
    {
        if (timestamp == 0) return "Bilinmiyor / Yok";
        std::time_t t = static_cast<std::time_t>(timestamp);
        std::tm tmBuffer{};
#if defined(_WIN32)
        gmtime_s(&tmBuffer, &t);
#else
        gmtime_r(&t, &tmBuffer);
#endif
        char buf[64];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tmBuffer);
        return std::string(buf);
    }
}

PEParser::PEParser(BinaryFile& binaryFile)
    : file(binaryFile), peOffset(0), machine(0), numberOfSections(0),
      timeDateStamp(0), characteristics(0), is64Bit(false),
      imageBase(0), entryPoint(0), subsystem(0), dllCharacteristics(0),
      optionalHeaderSize(0)
{
}

uint32_t PEParser::rvaToOffset(uint32_t rva) const
{
    for (const auto& sec : sections)
    {
        uint32_t secSize = std::max(sec.virtualSize, sec.rawSize);
        if (rva >= sec.virtualAddress && rva < sec.virtualAddress + secSize)
        {
            return sec.rawOffset + (rva - sec.virtualAddress);
        }
    }
    return 0;
}

void PEParser::parseImports(uint32_t importRva, uint32_t importSize)
{
    if (importRva == 0 || importSize == 0) return;

    uint32_t descriptorOffset = rvaToOffset(importRva);
    if (descriptorOffset == 0 || descriptorOffset >= file.getSize()) return;

    size_t fileSize = file.getSize();
    std::vector<std::string> imphashEntries;

    // IMAGE_IMPORT_DESCRIPTOR boyutu 20 byte
    while (descriptorOffset + 20 <= fileSize)
    {
        uint32_t originalFirstThunk = file.readUInt32(descriptorOffset);
        uint32_t nameRva = file.readUInt32(descriptorOffset + 12);
        uint32_t firstThunk = file.readUInt32(descriptorOffset + 16);

        // Sıfırlarla dolu descriptor import tablosunun sonudur
        if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
        {
            break;
        }

        std::string dllName;
        std::string cleanDll;

        if (nameRva != 0)
        {
            uint32_t nameOffset = rvaToOffset(nameRva);
            if (nameOffset != 0 && nameOffset < fileSize)
            {
                dllName = file.readAsciiString(nameOffset, 128);
                if (!dllName.empty())
                {
                    importedDlls.push_back(dllName);

                    cleanDll = dllName;
                    std::transform(cleanDll.begin(), cleanDll.end(), cleanDll.begin(), [](unsigned char c) {
                        return static_cast<char>(std::tolower(c));
                    });
                    size_t dotPos = cleanDll.rfind('.');
                    if (dotPos != std::string::npos)
                    {
                        std::string ext = cleanDll.substr(dotPos);
                        if (ext == ".dll" || ext == ".sys" || ext == ".ocx")
                        {
                            cleanDll = cleanDll.substr(0, dotPos);
                        }
                    }
                }
            }
        }

        // Fonksiyon isimlerini oku
        uint32_t thunkRva = (originalFirstThunk != 0) ? originalFirstThunk : firstThunk;
        if (thunkRva != 0)
        {
            uint32_t thunkOffset = rvaToOffset(thunkRva);
            size_t step = is64Bit ? 8 : 4;

            while (thunkOffset != 0 && thunkOffset + step <= fileSize)
            {
                uint64_t val = is64Bit ? file.readUInt64(thunkOffset) : file.readUInt32(thunkOffset);
                if (val == 0) break;

                // En yüksek bit set edilmişse import by ordinal'dir
                bool isOrdinal = is64Bit ? (val & 0x8000000000000000ULL) != 0 : (val & 0x80000000UL) != 0;
                if (!isOrdinal)
                {
                    uint32_t hintNameRva = static_cast<uint32_t>(val & 0x7FFFFFFF);
                    uint32_t hintNameOffset = rvaToOffset(hintNameRva);
                    if (hintNameOffset != 0 && hintNameOffset + 2 < fileSize)
                    {
                        // +2 bayt Hint değeri, sonrasında fonksiyon ismi gelir
                        std::string funcName = file.readAsciiString(hintNameOffset + 2, 128);
                        if (!funcName.empty())
                        {
                            importedFunctions.push_back(funcName);

                            if (!cleanDll.empty())
                            {
                                std::string cleanFunc = funcName;
                                std::transform(cleanFunc.begin(), cleanFunc.end(), cleanFunc.begin(), [](unsigned char c) {
                                    return static_cast<char>(std::tolower(c));
                                });
                                imphashEntries.push_back(cleanDll + "." + cleanFunc);
                            }
                        }
                    }
                }
                else
                {
                    if (!cleanDll.empty())
                    {
                        uint32_t ord = static_cast<uint32_t>(val & 0xFFFF);
                        imphashEntries.push_back(cleanDll + ".ord" + std::to_string(ord));
                    }
                }
                thunkOffset += static_cast<uint32_t>(step);
            }
        }

        descriptorOffset += 20;
    }

    if (!imphashEntries.empty())
    {
        std::ostringstream ss;
        for (size_t i = 0; i < imphashEntries.size(); ++i)
        {
            if (i > 0) ss << ",";
            ss << imphashEntries[i];
        }
        imphash = BinaryFile::computeMD5String(ss.str());
    }
}

void PEParser::parseExports(uint32_t exportRva, uint32_t exportSize)
{
    if (exportRva == 0 || exportSize == 0) return;
    uint32_t exportOffset = rvaToOffset(exportRva);
    if (exportOffset == 0 || exportOffset + 40 > file.getSize()) return;

    uint32_t nameRva = file.readUInt32(exportOffset + 12);
    if (nameRva != 0)
    {
        uint32_t nameOff = rvaToOffset(nameRva);
        if (nameOff != 0 && nameOff < file.getSize())
        {
            exportModuleName = file.readAsciiString(nameOff, 128);
        }
    }

    uint32_t numNames = file.readUInt32(exportOffset + 24);
    uint32_t namesRva = file.readUInt32(exportOffset + 32);
    uint32_t namesOff = rvaToOffset(namesRva);

    if (namesOff != 0 && numNames > 0)
    {
        size_t limit = std::min(static_cast<size_t>(numNames), static_cast<size_t>(1000));
        for (size_t i = 0; i < limit && (namesOff + i * 4 + 4) <= file.getSize(); ++i)
        {
            uint32_t funcNameRva = file.readUInt32(namesOff + static_cast<uint32_t>(i * 4));
            uint32_t funcNameOff = rvaToOffset(funcNameRva);
            if (funcNameOff != 0 && funcNameOff < file.getSize())
            {
                std::string fname = file.readAsciiString(funcNameOff, 128);
                if (!fname.empty())
                {
                    exportedFunctions.push_back(fname);
                }
            }
        }
    }
}

void PEParser::parseTls(uint32_t tlsRva, uint32_t tlsSize)
{
    if (tlsRva == 0 || tlsSize == 0) return;
    hasTls = true;
    uint32_t tlsOffset = rvaToOffset(tlsRva);
    if (tlsOffset == 0 || tlsOffset >= file.getSize()) return;

    // Callbacks dizisi VA: 32-bitte offset + 12, 64-bitte offset + 24
    uint64_t callbacksVA = 0;
    if (is64Bit)
    {
        if (tlsOffset + 32 <= file.getSize())
        {
            callbacksVA = file.readUInt64(tlsOffset + 24);
        }
    }
    else
    {
        if (tlsOffset + 16 <= file.getSize())
        {
            callbacksVA = file.readUInt32(tlsOffset + 12);
        }
    }

    if (callbacksVA >= imageBase)
    {
        uint32_t callbacksRva = static_cast<uint32_t>(callbacksVA - imageBase);
        uint32_t callbacksOffset = rvaToOffset(callbacksRva);
        if (callbacksOffset != 0)
        {
            size_t step = is64Bit ? 8 : 4;
            while (callbacksOffset + step <= file.getSize())
            {
                uint64_t cb = is64Bit ? file.readUInt64(callbacksOffset) : file.readUInt32(callbacksOffset);
                if (cb == 0) break;
                tlsCallbackAddresses.push_back(cb);
                callbacksOffset += static_cast<uint32_t>(step);
                if (tlsCallbackAddresses.size() >= 32) break;
            }
        }
    }
    tlsCallbacksCount = static_cast<uint32_t>(tlsCallbackAddresses.size());
}

void PEParser::detectCompiler()
{
    if (isDotNet)
    {
        compilerDetected = ".NET Framework / .NET Core (C# / VB.NET)";
        return;
    }

    const auto& data = file.getData();
    auto containsStr = [&](const std::string& pattern) -> bool {
        return MalwareAnalyzer::containsAsciiOrUtf16(data, pattern);
    };

    if (containsStr("rustc") || containsStr("cargo/registry"))
    {
        compilerDetected = "Rust (rustc)";
    }
    else if (containsStr("Go build ID") || containsStr("runtime.go") || containsStr("runtime.gopanic"))
    {
        compilerDetected = "Go (Golang)";
    }
    else if (containsStr("GCC:") || containsStr("mingw") || containsStr("__gxx_personality"))
    {
        compilerDetected = "MinGW / GCC (C/C++)";
    }
    else if (containsStr("Borland") || containsStr("Delphi") || containsStr("TApplication"))
    {
        compilerDetected = "Embarcadero Delphi / C++Builder";
    }
    else if (containsStr("clang") || containsStr("LLVM"))
    {
        compilerDetected = "LLVM / Clang";
    }
    else
    {
        bool hasMsvcRuntime = false;
        for (const auto& dll : importedDlls)
        {
            std::string d = dll;
            std::transform(d.begin(), d.end(), d.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (d.find("msvc") != std::string::npos || d.find("vcruntime") != std::string::npos || d.find("api-ms-win-crt") != std::string::npos)
            {
                hasMsvcRuntime = true;
                break;
            }
        }
        if (hasMsvcRuntime || containsStr("Microsoft Visual Studio") || containsStr("Rich"))
        {
            compilerDetected = "Microsoft Visual C/C++ (MSVC)";
        }
        else
        {
            compilerDetected = "Native Binary (C/C++ veya Assembly)";
        }
    }
}

void PEParser::disassembleEntryPoint()
{
    if (entryPoint == 0)
    {
        entryPointHexDump = "Entry Point 0 (DLL veya Resource Binary)";
        entryPointPrologue = "Yok";
        return;
    }

    uint32_t epOffset = rvaToOffset(entryPoint);
    if (epOffset == 0 || epOffset >= file.getSize())
    {
        entryPointHexDump = "Entry Point dosya sinirlari disinda!";
        entryPointPrologue = "Gecersiz Ofset";
        return;
    }

    size_t count = std::min(static_cast<size_t>(64), file.getSize() - epOffset);
    std::vector<uint8_t> epBytes = file.readBytes(epOffset, count);

    std::ostringstream ss;
    uint64_t epVA = imageBase + entryPoint;

    for (size_t row = 0; row < epBytes.size(); row += 16)
    {
        ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << (epVA + row) << "  ";
        for (size_t col = 0; col < 16; ++col)
        {
            if (row + col < epBytes.size())
            {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)epBytes[row + col] << " ";
            }
            else
            {
                ss << "   ";
            }
        }
        ss << " |";
        for (size_t col = 0; col < 16 && (row + col < epBytes.size()); ++col)
        {
            uint8_t c = epBytes[row + col];
            ss << ((c >= 32 && c <= 126) ? (char)c : '.');
        }
        ss << "|\r\n";
    }
    entryPointHexDump = ss.str();

    // Prologue analizi
    if (epBytes.size() >= 3)
    {
        if (epBytes[0] == 0x55 && epBytes[1] == 0x8B && epBytes[2] == 0xEC)
        {
            entryPointPrologue = "Standart x86 Fonksiyon Baslangici [push ebp; mov ebp, esp]";
        }
        else if (epBytes[0] == 0x55 && epBytes[1] == 0x89 && epBytes[2] == 0xE5)
        {
            entryPointPrologue = "GCC x86 Fonksiyon Baslangici [push ebp; mov ebp, esp]";
        }
        else if (epBytes.size() >= 4 && epBytes[0] == 0x48 && epBytes[1] == 0x83 && epBytes[2] == 0xEC)
        {
            std::ostringstream os;
            os << "Standart x64 Stack Tahsisi [sub rsp, 0x" << std::hex << (int)epBytes[3] << "]";
            entryPointPrologue = os.str();
        }
        else if (epBytes.size() >= 4 && epBytes[0] == 0x48 && epBytes[1] == 0x89 && epBytes[2] == 0x5C)
        {
            entryPointPrologue = "Standart x64 Register Save Prologue [mov [rsp+..], rbx]";
        }
        else if (epBytes[0] == 0xE9)
        {
            entryPointPrologue = "JMP Relative (Muhtemel Packer / Trampoline Stub)";
        }
        else if (epBytes[0] == 0xFF && epBytes[1] == 0x25)
        {
            entryPointPrologue = "JMP Indirect [IAT / Import Stub]";
        }
        else if (epBytes[0] == 0xCC)
        {
            entryPointPrologue = "INT 3 (Breakpoint / Debug Trap)";
        }
        else if (epBytes[0] == 0xE8)
        {
            entryPointPrologue = "CALL Relative (Dogrudan Alt Rutin Cagrısı)";
        }
        else
        {
            entryPointPrologue = "Ozel / Derleyiciye Ozgu Giris Kodu";
        }
    }
    else
    {
        entryPointPrologue = "Bilinmiyor";
    }
}

void PEParser::parse()
{
    if (file.getSize() < 0x40)
    {
        throw std::runtime_error("Dosya boyutu DOS Header icin cok kucuk.");
    }

    if (file.readByte(0) != 'M' || file.readByte(1) != 'Z')
    {
        throw std::runtime_error("Gecersiz DOS Header (MZ imzasi bulunamadi).");
    }

    peOffset = file.readUInt32(0x3C);
    if (peOffset + 24 > file.getSize())
    {
        throw std::runtime_error("Gecersiz PE Header ofseti (e_lfanew dosya boyutunu asiyor).");
    }

    // PE İmza kontrolü: 'P', 'E', 0x00, 0x00
    if (file.readByte(peOffset) != 'P' || file.readByte(peOffset + 1) != 'E' ||
        file.readByte(peOffset + 2) != 0 || file.readByte(peOffset + 3) != 0)
    {
        throw std::runtime_error("Gecersiz PE imzasi ('PE\\0\\0' bulunamadi).");
    }

    // COFF Header (20 byte)
    uint32_t coffOffset = peOffset + 4;
    machine = file.readUInt16(coffOffset);
    numberOfSections = file.readUInt16(coffOffset + 2);
    timeDateStamp = file.readUInt32(coffOffset + 4);
    optionalHeaderSize = file.readUInt16(coffOffset + 16);
    characteristics = file.readUInt16(coffOffset + 18);

    compileTimeStr = formatTimestamp(timeDateStamp);

    switch (machine)
    {
        case 0x014c: machineStr = "Intel 386 (x86 32-bit)"; break;
        case 0x8664: machineStr = "AMD64 / x86-64 (64-bit)"; break;
        case 0xaa64: machineStr = "ARM64 Little-Endian"; break;
        case 0x01c0: machineStr = "ARM Little-Endian"; break;
        default:     machineStr = "Bilinmeyen Mimari (0x" + [](uint16_t m){
            std::ostringstream ss; ss << std::hex << m; return ss.str();
        }(machine) + ")"; break;
    }

    // Optional Header
    uint32_t optOffset = coffOffset + 20;
    if (optionalHeaderSize > 0 && optOffset + optionalHeaderSize <= file.getSize())
    {
        uint16_t magic = file.readUInt16(optOffset);
        if (magic == 0x20B)
        {
            is64Bit = true; // PE32+
        }
        else if (magic == 0x10B)
        {
            is64Bit = false; // PE32
        }

        entryPoint = file.readUInt32(optOffset + 16);

        if (is64Bit)
        {
            imageBase = file.readUInt64(optOffset + 24);
            subsystem = file.readUInt16(optOffset + 68);
            dllCharacteristics = file.readUInt16(optOffset + 70);
        }
        else
        {
            imageBase = file.readUInt32(optOffset + 28);
            subsystem = file.readUInt16(optOffset + 68);
            dllCharacteristics = file.readUInt16(optOffset + 70);
        }

        switch (subsystem)
        {
            case 1:  subsystemStr = "Device Driver / Native"; break;
            case 2:  subsystemStr = "Windows GUI (Grafiksel Arayuz)"; break;
            case 3:  subsystemStr = "Windows CUI (Konsol Uygulamasi)"; break;
            case 7:  subsystemStr = "POSIX CUI"; break;
            case 9:  subsystemStr = "Windows CE GUI"; break;
            case 14: subsystemStr = "Xbox"; break;
            default: subsystemStr = "Diger / Bilinmiyor (" + std::to_string(subsystem) + ")"; break;
        }

        // Güvenlik Mitigasyonları (DllCharacteristics)
        mitigations.hasASLR = (dllCharacteristics & 0x0040) != 0;
        mitigations.hasDEP = (dllCharacteristics & 0x0100) != 0;
        mitigations.hasCFG = (dllCharacteristics & 0x4000) != 0;
        mitigations.hasHighEntropyVA = (dllCharacteristics & 0x0020) != 0;
        mitigations.hasSEH = (dllCharacteristics & 0x0400) == 0; // 0x0400 = NO_SEH
    }

    // Section Table
    uint32_t sectionTableOffset = optOffset + optionalHeaderSize;
    sections.clear();

    for (int i = 0; i < numberOfSections; ++i)
    {
        uint32_t secOffset = sectionTableOffset + (i * 40);
        if (secOffset + 40 > file.getSize()) break;

        PESection sec{};
        char rawName[9] = {0};
        for (int j = 0; j < 8; ++j)
        {
            rawName[j] = static_cast<char>(file.readByte(secOffset + j));
        }
        sec.name = std::string(rawName);

        sec.virtualSize = file.readUInt32(secOffset + 8);
        sec.virtualAddress = file.readUInt32(secOffset + 12);
        sec.rawSize = file.readUInt32(secOffset + 16);
        sec.rawOffset = file.readUInt32(secOffset + 20);
        sec.characteristics = file.readUInt32(secOffset + 36);

        sec.isReadable   = (sec.characteristics & 0x40000000) != 0;
        sec.isWritable   = (sec.characteristics & 0x80000000) != 0;
        sec.isExecutable = (sec.characteristics & 0x20000000) != 0;
        sec.isRWX        = sec.isWritable && sec.isExecutable;

        // Entropi hesabı
        if (sec.rawOffset < file.getSize() && sec.rawSize > 0)
        {
            size_t availableRaw = std::min(static_cast<size_t>(sec.rawSize), file.getSize() - sec.rawOffset);
            sec.entropy = BinaryFile::calculateEntropy(file.getData().data() + sec.rawOffset, availableRaw);
        }
        else
        {
            sec.entropy = 0.0;
        }

        sections.push_back(sec);
    }

    // Data Directory Ayrıştırma
    uint32_t dataDirBase = optOffset + (is64Bit ? 112 : 96);
    
    // 0. Export Directory
    if (dataDirBase + 8 <= optOffset + optionalHeaderSize && dataDirBase + 8 <= file.getSize())
    {
        uint32_t exportRva = file.readUInt32(dataDirBase);
        uint32_t exportSize = file.readUInt32(dataDirBase + 4);
        parseExports(exportRva, exportSize);
    }

    // 1. Import Directory
    if (dataDirBase + 16 <= optOffset + optionalHeaderSize && dataDirBase + 16 <= file.getSize())
    {
        uint32_t importRva = file.readUInt32(dataDirBase + 8);
        uint32_t importSize = file.readUInt32(dataDirBase + 12);
        parseImports(importRva, importSize);
    }

    // 4. Security (Certificate / Authenticode) Directory
    if (dataDirBase + 40 <= optOffset + optionalHeaderSize && dataDirBase + 40 <= file.getSize())
    {
        uint32_t secOffset = file.readUInt32(dataDirBase + 32);
        uint32_t secSize = file.readUInt32(dataDirBase + 36);
        if (secOffset != 0 && secSize > 0)
        {
            hasDigitalSignature = true;
            signatureSize = secSize;
        }
    }

    // 9. TLS Table
    if (dataDirBase + 80 <= optOffset + optionalHeaderSize && dataDirBase + 80 <= file.getSize())
    {
        uint32_t tlsRva = file.readUInt32(dataDirBase + 72);
        uint32_t tlsSize = file.readUInt32(dataDirBase + 76);
        parseTls(tlsRva, tlsSize);
    }

    // 14. CLR Runtime Header (.NET)
    if (dataDirBase + 120 <= optOffset + optionalHeaderSize && dataDirBase + 120 <= file.getSize())
    {
        uint32_t clrRva = file.readUInt32(dataDirBase + 112);
        uint32_t clrSize = file.readUInt32(dataDirBase + 116);
        if (clrRva != 0 && clrSize > 0)
        {
            isDotNet = true;
        }
    }

    // Overlay Tespiti
    uint32_t maxSectionEnd = 0;
    for (const auto& sec : sections)
    {
        uint32_t endOffset = sec.rawOffset + sec.rawSize;
        if (endOffset > maxSectionEnd) maxSectionEnd = endOffset;
    }
    if (file.getSize() > maxSectionEnd + 512 && maxSectionEnd > 0)
    {
        hasOverlay = true;
        overlaySize = file.getSize() - maxSectionEnd;
    }

    // Derleyici ve Entry Point Tersine Mühendislik Analizi
    detectCompiler();
    disassembleEntryPoint();
}

void PEParser::printReport() const
{
    std::cout << "\n======================================================\n";
    std::cout << "          PORTABLE EXECUTABLE (PE) RAPORU            \n";
    std::cout << "======================================================\n";

    std::cout << "Format             : " << (is64Bit ? "PE32+ (64-Bit)" : "PE32 (32-Bit)") << "\n";
    std::cout << "Mimari (Machine)   : " << machineStr << " [0x" << std::hex << machine << std::dec << "]\n";
    std::cout << "Derleme Zamani     : " << compileTimeStr << "\n";
    std::cout << "Subsystem          : " << subsystemStr << "\n";
    std::cout << "Image Base         : 0x" << std::hex << imageBase << "\n";
    std::cout << "Entry Point (RVA)  : 0x" << entryPoint << std::dec << "\n";
    std::cout << "Section Sayisi     : " << sections.size() << "\n";

    std::cout << "\n[+] Guvenlik Mitigasyonlari (Exploit Defenses):\n";
    std::cout << "  - ASLR (Dynamic Base)    : " << (mitigations.hasASLR ? "[AKTIF]" : "[KAPALI / RISKLİ]") << "\n";
    std::cout << "  - DEP / NX (No-Execute)  : " << (mitigations.hasDEP ? "[AKTIF]" : "[KAPALI / RISKLİ]") << "\n";
    std::cout << "  - Control Flow Guard     : " << (mitigations.hasCFG ? "[AKTIF]" : "[KAPALI]") << "\n";
    std::cout << "  - Structured Exception H.: " << (mitigations.hasSEH ? "[AKTIF]" : "[DEVRE DISI]") << "\n";

    std::cout << "\n[+] Bolumler (Sections) & Entropi Analizi:\n";
    std::cout << "----------------------------------------------------------------------------------\n";
    std::cout << std::left << std::setw(10) << "Isim"
              << std::setw(12) << "VirtAddr"
              << std::setw(12) << "VirtSize"
              << std::setw(12) << "RawSize"
              << std::setw(10) << "Entropi"
              << std::setw(12) << "Izinler"
              << "Durum\n";
    std::cout << "----------------------------------------------------------------------------------\n";

    for (const auto& sec : sections)
    {
        std::string perms;
        if (sec.isReadable) perms += "R";
        if (sec.isWritable) perms += "W";
        if (sec.isExecutable) perms += "X";

        std::string status = "Normal";
        if (sec.isRWX)
        {
            status = "!! RWX (SUPHELI) !!";
        }
        else if (sec.entropy > 7.0)
        {
            status = "* Yuksek Entropi (Packed?) *";
        }

        std::cout << std::left << std::setw(10) << sec.name
                  << "0x" << std::setw(10) << std::hex << sec.virtualAddress
                  << "0x" << std::setw(10) << sec.virtualSize
                  << "0x" << std::setw(10) << sec.rawSize << std::dec
                  << std::fixed << std::setprecision(2) << std::setw(10) << sec.entropy
                  << std::setw(12) << perms
                  << status << "\n";
    }
    std::cout << "----------------------------------------------------------------------------------\n";

    if (!importedDlls.empty())
    {
        std::cout << "\n[+] Bagimli DLL'ler (" << importedDlls.size() << " adet):\n";
        for (size_t i = 0; i < importedDlls.size() && i < 15; ++i)
        {
            std::cout << "  * " << importedDlls[i] << "\n";
        }
        if (importedDlls.size() > 15)
        {
            std::cout << "  ... ve " << (importedDlls.size() - 15) << " DLL daha.\n";
        }
    }

    if (!imphash.empty())
    {
        std::cout << "\n[+] Imphash (Import Hash) : " << imphash << "\n";
    }

    std::cout << "[+] Derleyici / Tooling    : " << compilerDetected << "\n";
    if (isDotNet)
    {
        std::cout << "    * .NET / CLR Runtime Header tespit edildi.\n";
    }

    if (hasTls)
    {
        std::cout << "[+] TLS Directory          : [MEVCUT] (" << tlsCallbacksCount << " adet callback)\n";
        for (auto addr : tlsCallbackAddresses)
        {
            std::cout << "    * Callback RVA/VA      : 0x" << std::hex << addr << std::dec << "\n";
        }
    }

    if (!entryPointHexDump.empty())
    {
        std::cout << "\n[+] Entry Point Analizi & Prologue:\n";
        std::cout << "    Prologue Tespiti       : " << entryPointPrologue << "\n";
        std::cout << "----------------------------------------------------------------------------------\n";
        std::cout << entryPointHexDump;
        std::cout << "----------------------------------------------------------------------------------\n";
    }

    // Malware Analiz motorunu tetikle
    MalwareAnalyzer::analyzePE(*this, file);
}
