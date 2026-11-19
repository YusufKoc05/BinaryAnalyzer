#include "ELFParser.h"
#include "MalwareAnalyzer.h"

#include <iostream>
#include <iomanip>
#include <sstream>

ELFParser::ELFParser(BinaryFile& binaryFile)
    : file(binaryFile), is64Bit(false), isLittleEndian(true), osAbi(0),
      elfType(0), machine(0), entryPoint(0), shOffset(0), shCount(0),
      shStrIndex(0), executableStack(false)
{
}

void ELFParser::parse()
{
    if (file.getSize() < 52)
    {
        throw std::runtime_error("Dosya boyutu ELF Header icin yetersiz.");
    }

    // Magic: 0x7F, 'E', 'L', 'F'
    if (file.readByte(0) != 0x7F || file.readByte(1) != 'E' ||
        file.readByte(2) != 'L' || file.readByte(3) != 'F')
    {
        throw std::runtime_error("Gecersiz ELF imzasi (0x7F 'ELF' bulunamadi).");
    }

    uint8_t elfClass = file.readByte(4);
    is64Bit = (elfClass == 2);

    uint8_t dataEncoding = file.readByte(5);
    isLittleEndian = (dataEncoding == 1);

    osAbi = file.readByte(7);
    switch (osAbi)
    {
        case 0:  osAbiStr = "UNIX - System V"; break;
        case 1:  osAbiStr = "HP-UX"; break;
        case 2:  osAbiStr = "NetBSD"; break;
        case 3:  osAbiStr = "Linux"; break;
        case 6:  osAbiStr = "Solaris"; break;
        case 9:  osAbiStr = "FreeBSD"; break;
        case 12: osAbiStr = "OpenBSD"; break;
        default: osAbiStr = "Diger / Bilinmiyor (" + std::to_string(osAbi) + ")"; break;
    }

    elfType = file.readUInt16(16);
    switch (elfType)
    {
        case 1: elfTypeStr = "ET_REL (Relocatable object file)"; break;
        case 2: elfTypeStr = "ET_EXEC (Executable file)"; break;
        case 3: elfTypeStr = "ET_DYN (Shared object / PIE Position-Independent Executable)"; break;
        case 4: elfTypeStr = "ET_CORE (Core file)"; break;
        default: elfTypeStr = "Bilinmeyen Tip (" + std::to_string(elfType) + ")"; break;
    }

    machine = file.readUInt16(18);
    switch (machine)
    {
        case 3:   machineStr = "x86 (Intel 80386)"; break;
        case 40:  machineStr = "ARM (32-bit)"; break;
        case 62:  machineStr = "x86-64 (AMD64)"; break;
        case 183: machineStr = "AArch64 (ARM 64-bit)"; break;
        case 243: machineStr = "RISC-V"; break;
        case 8:   machineStr = "MIPS"; break;
        default:  machineStr = "Bilinmeyen Mimari (0x" + [](uint16_t m){
            std::ostringstream ss; ss << std::hex << m; return ss.str();
        }(machine) + ")"; break;
    }

    uint64_t phOffset = 0;
    uint16_t phCount = 0;
    uint16_t phEntrySize = 0;
    uint16_t shEntrySize = 0;

    if (is64Bit)
    {
        if (file.getSize() < 64)
        {
            throw std::runtime_error("Dosya boyutu 64-bit ELF Header icin yetersiz.");
        }
        entryPoint = file.readUInt64(24);
        phOffset = file.readUInt64(32);
        shOffset = file.readUInt64(40);
        phEntrySize = file.readUInt16(54);
        phCount = file.readUInt16(56);
        shEntrySize = file.readUInt16(58);
        shCount = file.readUInt16(60);
        shStrIndex = file.readUInt16(62);
    }
    else
    {
        entryPoint = file.readUInt32(24);
        phOffset = file.readUInt32(28);
        shOffset = file.readUInt32(32);
        phEntrySize = file.readUInt16(42);
        phCount = file.readUInt16(44);
        shEntrySize = file.readUInt16(46);
        shCount = file.readUInt16(48);
        shStrIndex = file.readUInt16(50);
    }

    // Program Headers kontrolü (Executable Stack - PT_GNU_STACK 0x6474e551)
    executableStack = false;
    for (uint16_t i = 0; i < phCount; ++i)
    {
        uint64_t currPh = phOffset + (i * phEntrySize);
        if (currPh + phEntrySize > file.getSize()) break;

        uint32_t pType = file.readUInt32(currPh);
        if (pType == 0x6474e551) // PT_GNU_STACK
        {
            uint32_t pFlags = is64Bit ? file.readUInt32(currPh + 4) : file.readUInt32(currPh + 24);
            if (pFlags & 0x1) // PF_X
            {
                executableStack = true;
            }
        }
    }

    // Section Headers ve Section Name String Table
    sections.clear();
    if (shOffset > 0 && shCount > 0 && shStrIndex < shCount)
    {
        uint64_t strTableHdrOffset = shOffset + (shStrIndex * shEntrySize);
        uint64_t strTableOffset = 0;
        uint64_t strTableSize = 0;

        if (is64Bit)
        {
            if (strTableHdrOffset + 64 <= file.getSize())
            {
                strTableOffset = file.readUInt64(strTableHdrOffset + 24);
                strTableSize = file.readUInt64(strTableHdrOffset + 32);
            }
        }
        else
        {
            if (strTableHdrOffset + 40 <= file.getSize())
            {
                strTableOffset = file.readUInt32(strTableHdrOffset + 16);
                strTableSize = file.readUInt32(strTableHdrOffset + 20);
            }
        }

        for (uint16_t i = 0; i < shCount; ++i)
        {
            uint64_t currSh = shOffset + (i * shEntrySize);
            if (currSh + shEntrySize > file.getSize()) break;

            ELFSection sec{};
            uint32_t nameOffsetInStr = file.readUInt32(currSh);

            if (strTableOffset > 0 && (strTableOffset + nameOffsetInStr) < file.getSize())
            {
                sec.name = file.readAsciiString(strTableOffset + nameOffsetInStr, 64);
            }

            if (is64Bit)
            {
                sec.type = file.readUInt32(currSh + 4);
                sec.flags = file.readUInt64(currSh + 8);
                sec.addr = file.readUInt64(currSh + 16);
                sec.offset = file.readUInt64(currSh + 24);
                sec.size = file.readUInt64(currSh + 32);
            }
            else
            {
                sec.type = file.readUInt32(currSh + 4);
                sec.flags = file.readUInt32(currSh + 8);
                sec.addr = file.readUInt32(currSh + 12);
                sec.offset = file.readUInt32(currSh + 16);
                sec.size = file.readUInt32(currSh + 20);
            }

            // SHF_WRITE = 0x1, SHF_ALLOC = 0x2, SHF_EXECINSTR = 0x4
            sec.isWritable = (sec.flags & 0x1) != 0;
            sec.isAlloc = (sec.flags & 0x2) != 0;
            sec.isExecutable = (sec.flags & 0x4) != 0;
            sec.isRWX = sec.isWritable && sec.isExecutable;

            // Section Entropi Hesabı
            if (sec.offset < file.getSize() && sec.size > 0 && sec.type != 8 /* SHT_NOBITS */)
            {
                size_t actualSize = std::min(static_cast<size_t>(sec.size), file.getSize() - sec.offset);
                sec.entropy = BinaryFile::calculateEntropy(file.getData().data() + sec.offset, actualSize);
            }
            else
            {
                sec.entropy = 0.0;
            }

            sections.push_back(sec);
        }
    }
}

void ELFParser::printReport() const
{
    std::cout << "\n======================================================\n";
    std::cout << "          ELF (LINUX / UNIX BINARY) RAPORU            \n";
    std::cout << "======================================================\n";

    std::cout << "Format             : " << (is64Bit ? "ELF64 (64-Bit)" : "ELF32 (32-Bit)") << "\n";
    std::cout << "Endianness         : " << (isLittleEndian ? "Little Endian (LSB)" : "Big Endian (MSB)") << "\n";
    std::cout << "OS / ABI           : " << osAbiStr << "\n";
    std::cout << "Dosya Tipi (Type)  : " << elfTypeStr << "\n";
    std::cout << "Mimari (Machine)   : " << machineStr << "\n";
    std::cout << "Entry Point        : 0x" << std::hex << entryPoint << std::dec << "\n";
    std::cout << "Section Sayisi     : " << sections.size() << "\n";

    std::cout << "\n[+] Linux Guvenlik Bayraklari:\n";
    std::cout << "  - Executable Stack (NX)  : " << (executableStack ? "[TEHLIKE: Stack Executable!]" : "[GUVENLI: Stack No-Exec]") << "\n";

    if (!sections.empty())
    {
        std::cout << "\n[+] Bolumler (Sections) & Entropi Analizi:\n";
        std::cout << "----------------------------------------------------------------------------------\n";
        std::cout << std::left << std::setw(18) << "Isim"
                  << std::setw(14) << "Adres"
                  << std::setw(12) << "Boyut"
                  << std::setw(10) << "Entropi"
                  << std::setw(10) << "Bayraklar"
                  << "Durum\n";
        std::cout << "----------------------------------------------------------------------------------\n";

        for (const auto& sec : sections)
        {
            if (sec.name.empty()) continue;

            std::string flagsStr;
            if (sec.isAlloc) flagsStr += "A";
            if (sec.isWritable) flagsStr += "W";
            if (sec.isExecutable) flagsStr += "X";

            std::string status = "Normal";
            if (sec.isRWX)
            {
                status = "!! RWX (SUPHELI) !!";
            }
            else if (sec.entropy > 7.0)
            {
                status = "* Yuksek Entropi *";
            }

            std::cout << std::left << std::setw(18) << sec.name
                      << "0x" << std::setw(12) << std::hex << sec.addr
                      << "0x" << std::setw(10) << sec.size << std::dec
                      << std::fixed << std::setprecision(2) << std::setw(10) << sec.entropy
                      << std::setw(10) << flagsStr
                      << status << "\n";
        }
        std::cout << "----------------------------------------------------------------------------------\n";
    }

    MalwareAnalyzer::analyzeELF(*this, file);
}
