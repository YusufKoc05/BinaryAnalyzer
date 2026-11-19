#include <iostream>
#include <iomanip>
#include <sstream>
#include <memory>
#include <string>

#include "BinaryFile.h"
#include "PEParser.h"
#include "ELFParser.h"

namespace
{
    void printBanner()
    {
        std::cout << "======================================================================\n";
        std::cout << "        ____  _                             _                         \n";
        std::cout << "       | __ )(_)_ __   __ _ _ __ _   _     / \\   _ __   __ _          \n";
        std::cout << "       |  _ \\| | '_ \\ / _` | '__| | | |   / _ \\ | '_ \\ / _` |         \n";
        std::cout << "       | |_) | | | | | (_| | |  | |_| |  / ___ \\| | | | (_| |         \n";
        std::cout << "       |____/|_|_| |_|\\__,_|_|   \\__, | /_/   \\_\\_| |_|\\__,_|         \n";
        std::cout << "                                 |___/                                \n";
        std::cout << "     Advanced Static Binary & Malware Threat Analyzer v2.0            \n";
        std::cout << "======================================================================\n";
    }

    std::string formatSize(size_t bytes)
    {
        std::ostringstream ss;
        if (bytes < 1024)
        {
            ss << bytes << " Byte";
        }
        else if (bytes < 1024 * 1024)
        {
            ss << std::fixed << std::setprecision(2) << (bytes / 1024.0) << " KB (" << bytes << " Byte)";
        }
        else
        {
            ss << std::fixed << std::setprecision(2) << (bytes / (1024.0 * 1024.0)) << " MB (" << bytes << " Byte)";
        }
        return ss.str();
    }
}

int main(int argc, char* argv[])
{
    printBanner();

    std::string filePath;
    if (argc < 2)
    {
        std::cout << "\n[?] Analiz edilecek dosya yolunu girin (veya dosyayi terminale surukleyip Enter'a basin):\n> ";
        std::getline(std::cin, filePath);
        if (filePath.size() >= 2 && filePath.front() == '"' && filePath.back() == '"')
        {
            filePath = filePath.substr(1, filePath.size() - 2);
        }
        if (filePath.empty())
        {
            std::cout << "[-] Dosya yolu girilmedi. Cikis yapiliyor.\n";
            return 1;
        }
    }
    else
    {
        filePath = argv[1];
    }

    try
    {
        std::cout << "[*] Dosya yukleniyor: " << filePath << " ...\n";
        BinaryFile binary(filePath);

        std::cout << "[+] Dosya Basariyla Okundu!\n";
        std::cout << "------------------------------------------------------\n";
        std::cout << "Dosya Yolu      : " << binary.getFilePath() << "\n";
        std::cout << "Dosya Boyutu    : " << formatSize(binary.getSize()) << "\n";
        std::cout << "MD5 Hash        : " << binary.getMD5() << "\n";
        std::cout << "SHA-1 Hash      : " << binary.getSHA1() << "\n";
        std::cout << "SHA-256 Hash    : " << binary.getSHA256() << "\n";
        std::cout << "Genel Entropi   : " << std::fixed << std::setprecision(4)
                  << binary.getOverallEntropy() << " / 8.0000";

        if (binary.getOverallEntropy() > 7.2)
        {
            std::cout << " (DIKKAT: Cok yuksek entropi! Dosya muhtemelen paketlenmis/sifrelenmis)";
        }
        std::cout << "\n------------------------------------------------------\n";

        if (binary.getSize() < 4)
        {
            std::cout << "[-] Hata: Dosya boyutu binary analizi icin cok kucuk.\n";
            return 1;
        }

        std::unique_ptr<IParser> parser = nullptr;

        // PE Kontrolü (DOS MZ)
        if (binary.readByte(0) == 'M' && binary.readByte(1) == 'Z')
        {
            parser = std::make_unique<PEParser>(binary);
        }
        // ELF Kontrolü (0x7F, 'E', 'L', 'F')
        else if (binary.readByte(0) == 0x7F &&
                 binary.readByte(1) == 'E' &&
                 binary.readByte(2) == 'L' &&
                 binary.readByte(3) == 'F')
        {
            parser = std::make_unique<ELFParser>(binary);
        }
        // Mach-O Kontrolü (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE)
        else if ((binary.readByte(0) == 0xCF && binary.readByte(1) == 0xFA && binary.readByte(2) == 0xED && binary.readByte(3) == 0xFE) ||
                 (binary.readByte(0) == 0xFE && binary.readByte(1) == 0xED && binary.readByte(2) == 0xFA && binary.readByte(3) == 0xCF))
        {
            std::cout << "\n[!] Dosya Formati: Apple Mach-O Binary (Henuz tam ayristirma destegi eklenmedi).\n";
            return 0;
        }
        else
        {
            std::cout << "\n[-] Bilinmeyen dosya tipi veya desteklenmeyen format.\n";
            std::cout << "    Ilk 4 bayt: 0x" << std::hex
                      << (int)binary.readByte(0) << " "
                      << (int)binary.readByte(1) << " "
                      << (int)binary.readByte(2) << " "
                      << (int)binary.readByte(3) << std::dec << "\n";
            return 1;
        }

        if (parser)
        {
            parser->parse();
            parser->printReport();
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "\n[-] Kritik Hata Olustu: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\n[*] Analiz tamamlandi.\n";
    return 0;
}
