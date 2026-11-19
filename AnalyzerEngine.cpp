#include "AnalyzerEngine.h"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>

namespace
{
    std::string formatFileSize(size_t bytes)
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

    std::string getBaseFileName(const std::string& path)
    {
        size_t pos = path.find_last_of("/\\");
        if (pos == std::string::npos) return path;
        return path.substr(pos + 1);
    }

    std::string escapeJson(const std::string& s)
    {
        std::ostringstream o;
        for (char c : s)
        {
            if (c == '"') o << "\\\"";
            else if (c == '\\') o << "\\\\";
            else if (c == '\b') o << "\\b";
            else if (c == '\f') o << "\\f";
            else if (c == '\n') o << "\\n";
            else if (c == '\r') o << "\\r";
            else if (c == '\t') o << "\\t";
            else if (static_cast<unsigned char>(c) <= 0x1f)
            {
                o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
            }
            else
            {
                o << c;
            }
        }
        return o.str();
    }
}

AnalysisResult AnalyzerEngine::analyze(const std::string& filePath)
{
    AnalysisResult res;
    res.filePath = filePath;
    res.fileName = getBaseFileName(filePath);

    try
    {
        BinaryFile binary(filePath);
        res.fileSize = binary.getSize();
        res.formattedSize = formatFileSize(res.fileSize);
        res.md5 = binary.getMD5();
        res.sha1 = binary.getSHA1();
        res.sha256 = binary.getSHA256();
        res.overallEntropy = binary.getOverallEntropy();
        res.isPackedOrEncrypted = (res.overallEntropy > 7.15);

        if (binary.getSize() < 4)
        {
            res.success = false;
            res.errorMessage = "Dosya boyutu binary analizi icin cok kucuk.";
            return res;
        }

        // Stringler ve IOC Taraması
        res.extractedStrings = binary.extractStrings(4, 3000);
        for (const auto& strItem : res.extractedStrings)
        {
            const std::string& s = strItem.value;

            // URL tespiti (Meşru şema ve sertifika URL'leri filtrelenir)
            if (s.find("http://") != std::string::npos || s.find("https://") != std::string::npos)
            {
                if (!MalwareAnalyzer::isLegitimateUrl(s))
                {
                    if (std::find(res.detectedIocUrls.begin(), res.detectedIocUrls.end(), s) == res.detectedIocUrls.end())
                    {
                        res.detectedIocUrls.push_back(s);
                    }
                }
            }

            // Basit IP kalıbı (örn: x.x.x.x)
            static const std::regex ipRegex(R"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)");
            if (std::regex_search(s, ipRegex))
            {
                if (std::find(res.detectedIocIps.begin(), res.detectedIocIps.end(), s) == res.detectedIocIps.end())
                {
                    res.detectedIocIps.push_back(s);
                }
            }

            // Şüpheli Komut Satırları
            if (s.find("powershell -enc") != std::string::npos ||
                s.find("-ExecutionPolicy Bypass") != std::string::npos ||
                s.find("vssadmin delete shadows") != std::string::npos ||
                s.find("certutil -urlcache") != std::string::npos)
            {
                if (std::find(res.detectedIocCommands.begin(), res.detectedIocCommands.end(), s) == res.detectedIocCommands.end())
                {
                    res.detectedIocCommands.push_back(s);
                }
            }
        }

        std::ostringstream report;
        report << "======================================================\n";
        report << "     STATIK BINARY & TEHDIT ANALIZ RAPORU (v2.0)      \n";
        report << "======================================================\n";
        report << "Dosya Adi    : " << res.fileName << "\n";
        report << "Dosya Yolu   : " << res.filePath << "\n";
        report << "Dosya Boyutu : " << res.formattedSize << "\n";
        report << "MD5 Hash     : " << res.md5 << "\n";
        report << "SHA-1 Hash   : " << res.sha1 << "\n";
        report << "SHA-256 Hash : " << res.sha256 << "\n";
        report << "Genel Entropi: " << std::fixed << std::setprecision(4)
               << res.overallEntropy << " / 8.0000";
        if (res.isPackedOrEncrypted)
        {
            report << " [DIKKAT: Cok yuksek entropi! Packed/Crypt suphesi!]";
        }
        report << "\n\n";

        // PE Formatı
        if (binary.readByte(0) == 'M' && binary.readByte(1) == 'Z')
        {
            PEParser pe(binary);
            pe.parse();

            res.is64Bit = pe.getIs64Bit();
            res.formatName = res.is64Bit ? "PE32+ (Windows 64-Bit)" : "PE32 (Windows 32-Bit)";
            res.architecture = pe.getMachineStr();
            res.subsystem = pe.getSubsystemStr();
            res.compileTime = pe.getCompileTimeStr();
            res.entryPoint = pe.getEntryPoint();
            res.mitigations = pe.getMitigations();
            res.peSections = pe.getSections();
            res.importedDlls = pe.getImportedDlls();
            res.importedFunctions = pe.getImportedFunctions();

            res.hasDigitalSignature = pe.getHasDigitalSignature();
            res.signatureSize = pe.getSignatureSize();
            res.hasOverlay = pe.getHasOverlay();
            res.overlaySize = pe.getOverlaySize();
            res.exportModuleName = pe.getExportModuleName();
            res.exportedFunctions = pe.getExportedFunctions();

            res.imphash = pe.getImphash();
            res.compilerDetected = pe.getCompilerDetected();
            res.isDotNet = pe.getIsDotNet();
            res.hasTls = pe.getHasTls();
            res.tlsCallbacksCount = pe.getTlsCallbacksCount();
            res.tlsCallbackAddresses = pe.getTlsCallbackAddresses();
            res.entryPointHexDump = pe.getEntryPointHexDump();
            res.entryPointPrologue = pe.getEntryPointPrologue();

            MalwareAnalyzer::evaluatePE(pe, binary, res.riskScore, res.riskLevel, res.findings, res.categorizedDetections);

            // Anormal Boyutta Gizli Overlay Verisi (Sertifikasız ve > 64 KB ise)
            if (res.hasOverlay && !res.hasDigitalSignature && res.overlaySize > 65536)
            {
                res.riskScore += 20;
                res.findings.push_back({
                    "Anomali & Steganografi",
                    "Dosya arkasina gizlenmis yuksek boyutlu veri (Overlay): " + formatFileSize(res.overlaySize),
                    20,
                    "T1027",
                    "Defense Evasion: Steganography / Overlay Data"
                });
                res.riskLevel = MalwareAnalyzer::calculateRiskLevel(res.riskScore);
            }

            report << "--- [ FORMAT & HEADER BILGILERI ] ---\n";
            report << "Format           : " << res.formatName << "\n";
            report << "Mimari           : " << res.architecture << "\n";
            report << "Subsystem        : " << res.subsystem << "\n";
            report << "Derleyici / Arac : " << res.compilerDetected << "\n";
            report << "Derleme Zamani   : " << res.compileTime << "\n";
            report << "Entry Point (RVA): 0x" << std::hex << res.entryPoint << std::dec << "\n";
            report << "EP Analizi       : " << res.entryPointPrologue << "\n";
            if (!res.imphash.empty()) report << "Import Hash (MD5): " << res.imphash << "\n";
            report << "TLS Callback     : " << (res.hasTls ? ("VAR (" + std::to_string(res.tlsCallbacksCount) + " callback)") : "Yok") << "\n";
            report << "Dijital Imza     : " << (res.hasDigitalSignature ? "Mevcut (" + std::to_string(res.signatureSize) + " Byte)" : "Yok / Imzasiz") << "\n";
            report << "Overlay Verisi   : " << (res.hasOverlay ? "Var (" + formatFileSize(res.overlaySize) + " ek veri)" : "Yok") << "\n\n";

            report << "--- [ EXPLOIT KORUMA MEKANIZMALARI ] ---\n";
            report << "  * ASLR (Dynamic Base)    : " << (res.mitigations.hasASLR ? "Aktif" : "Devre Disi (Riskli)") << "\n";
            report << "  * DEP / NX (No-Execute)  : " << (res.mitigations.hasDEP ? "Aktif" : "Devre Disi (Riskli)") << "\n";
            report << "  * Control Flow Guard     : " << (res.mitigations.hasCFG ? "Aktif" : "Kapali") << "\n";
            report << "  * Structured Exception H.: " << (res.mitigations.hasSEH ? "Aktif" : "Devre Disi") << "\n\n";

            report << "--- [ BOLUMLER (SECTIONS) ] ---\n";
            for (const auto& sec : res.peSections)
            {
                std::string perms;
                if (sec.isReadable) perms += "R";
                if (sec.isWritable) perms += "W";
                if (sec.isExecutable) perms += "X";

                report << "  * " << std::left << std::setw(10) << sec.name
                       << " | Virt: 0x" << std::hex << sec.virtualAddress
                       << " | RawSize: 0x" << sec.rawSize << std::dec
                       << " | Entropi: " << std::fixed << std::setprecision(2) << sec.entropy
                       << " | Izinler: " << perms;
                if (sec.isRWX) report << " [!! RWX SUPHELI !!]";
                else if (sec.entropy > 7.1) report << " [* YUKSEK ENTROPI *]";
                report << "\n";
            }
            report << "\n";

            if (!res.exportedFunctions.empty())
            {
                report << "--- [ DISA AKTARILAN FONKSIYONLAR (EXPORTS: " << res.exportedFunctions.size() << ") ] ---\n";
                if (!res.exportModuleName.empty()) report << "Modul Ismi: " << res.exportModuleName << "\n";
                for (size_t i = 0; i < res.exportedFunctions.size() && i < 20; ++i)
                {
                    report << "  * " << res.exportedFunctions[i] << "\n";
                }
                if (res.exportedFunctions.size() > 20) report << "  ... ve " << (res.exportedFunctions.size() - 20) << " fonksiyon daha.\n";
                report << "\n";
            }

            if (!res.importedDlls.empty())
            {
                report << "--- [ BAGIMLI DLL'LER (" << res.importedDlls.size() << ") ] ---\n";
                for (const auto& dll : res.importedDlls)
                {
                    report << "  * " << dll << "\n";
                }
                report << "\n";
            }
        }
        // ELF Formatı
        else if (binary.readByte(0) == 0x7F &&
                 binary.readByte(1) == 'E' &&
                 binary.readByte(2) == 'L' &&
                 binary.readByte(3) == 'F')
        {
            ELFParser elf(binary);
            elf.parse();

            res.is64Bit = elf.getIs64Bit();
            res.formatName = res.is64Bit ? "ELF64 (Linux 64-Bit)" : "ELF32 (Linux 32-Bit)";
            res.architecture = elf.getMachineStr();
            res.subsystem = "Linux / Unix Userland";
            res.elfOsAbi = elf.getOsAbiStr();
            res.entryPoint = elf.getEntryPoint();
            res.elfExecutableStack = elf.hasExecutableStack();
            res.elfSections = elf.getSections();

            MalwareAnalyzer::evaluateELF(elf, binary, res.riskScore, res.riskLevel, res.findings, res.categorizedDetections);

            report << "--- [ FORMAT & HEADER BILGILERI ] ---\n";
            report << "Format           : " << res.formatName << "\n";
            report << "Mimari           : " << res.architecture << "\n";
            report << "OS / ABI         : " << res.elfOsAbi << "\n";
            report << "Entry Point      : 0x" << std::hex << res.entryPoint << std::dec << "\n\n";

            report << "--- [ GUVENLIK KONTROLLERI ] ---\n";
            report << "  * Executable Stack (NX)  : " << (res.elfExecutableStack ? "TEHLIKE: Stack Executable!" : "Guvenli (No-Exec)") << "\n\n";

            report << "--- [ BOLUMLER (SECTIONS) ] ---\n";
            for (const auto& sec : res.elfSections)
            {
                if (sec.name.empty()) continue;
                std::string perms;
                if (sec.isAlloc) perms += "A";
                if (sec.isWritable) perms += "W";
                if (sec.isExecutable) perms += "X";

                report << "  * " << std::left << std::setw(16) << sec.name
                       << " | Adres: 0x" << std::hex << sec.addr
                       << " | Boyut: 0x" << sec.size << std::dec
                       << " | Entropi: " << std::fixed << std::setprecision(2) << sec.entropy
                       << " | Bayraklar: " << perms;
                if (sec.isRWX) report << " [!! RWX SUPHELI !!]";
                else if (sec.entropy > 7.1) report << " [* YUKSEK ENTROPI *]";
                report << "\n";
            }
            report << "\n";
        }
        else
        {
            res.success = false;
            res.errorMessage = "Desteklenmeyen dosya formati (Yalnizca PE ve ELF dosyalari desteklenmektedir).";
            return res;
        }

        // Tehdit Raporu
        report << "======================================================\n";
        report << "           STATIK MALWARE & TEHDIT RAPORU             \n";
        report << "======================================================\n";
        report << "Risk Skoru    : " << res.riskScore << "/100+\n";
        report << "Risk Seviyesi : " << res.riskLevel << "\n\n";

        report << "[+] Tespit Edilen Supheli Davranislar & API'ler:\n";
        if (res.categorizedDetections.empty())
        {
            report << "  - Temiz: Ozel bir supheli API oruntusu tespit edilmedi.\n";
        }
        else
        {
            for (const auto& cat : res.categorizedDetections)
            {
                report << "  [" << cat.first << "]\n";
                for (const auto& api : cat.second)
                {
                    report << "    * " << api << "\n";
                }
            }
        }
        report << "\n[+] Tehdit Bulgulari & MITRE ATT&CK(R) Eslestirmesi:\n";
        if (res.findings.empty())
        {
            report << "  - Guvenlik anomalisi tespit edilmedi.\n";
        }
        else
        {
            for (const auto& f : res.findings)
            {
                report << "  [+" << f.weight << "] (" << f.category << ") " << f.detail;
                if (!f.mitreId.empty() && f.mitreId != "-")
                {
                    report << " [MITRE: " << f.mitreId << " - " << f.mitreTactic << "]";
                }
                report << "\n";
            }
        }

        if (!res.detectedIocUrls.empty() || !res.detectedIocIps.empty() || !res.detectedIocCommands.empty())
        {
            report << "\n[+] Tespit Edilen IOC (Gostergeler):\n";
            for (const auto& u : res.detectedIocUrls) report << "  * URL    : " << u << "\n";
            for (const auto& ip : res.detectedIocIps) report << "  * IP     : " << ip << "\n";
            for (const auto& c : res.detectedIocCommands) report << "  * Komut  : " << c << "\n";
        }

        if (!res.entryPointHexDump.empty())
        {
            report << "\n--- [ ENTRY POINT OPCODES & HEX INSPECTOR ] ---\n";
            report << res.entryPointHexDump << "\n";
        }

        res.fullReportText = report.str();
        res.success = true;
    }
    catch (const std::exception& e)
    {
        res.success = false;
        res.errorMessage = e.what();
    }

    return res;
}

std::string AnalysisResult::generateJsonReport() const
{
    std::ostringstream j;
    j << "{\n";
    j << "  \"fileName\": \"" << escapeJson(fileName) << "\",\n";
    j << "  \"filePath\": \"" << escapeJson(filePath) << "\",\n";
    j << "  \"fileSize\": " << fileSize << ",\n";
    j << "  \"md5\": \"" << md5 << "\",\n";
    j << "  \"sha1\": \"" << sha1 << "\",\n";
    j << "  \"sha256\": \"" << sha256 << "\",\n";
    j << "  \"imphash\": \"" << imphash << "\",\n";
    j << "  \"compiler\": \"" << escapeJson(compilerDetected) << "\",\n";
    j << "  \"isDotNet\": " << (isDotNet ? "true" : "false") << ",\n";
    j << "  \"hasTls\": " << (hasTls ? "true" : "false") << ",\n";
    j << "  \"tlsCallbacksCount\": " << tlsCallbacksCount << ",\n";
    j << "  \"entropy\": " << overallEntropy << ",\n";
    j << "  \"format\": \"" << escapeJson(formatName) << "\",\n";
    j << "  \"architecture\": \"" << escapeJson(architecture) << "\",\n";
    j << "  \"riskScore\": " << riskScore << ",\n";
    j << "  \"riskLevel\": \"" << escapeJson(riskLevel) << "\",\n";
    j << "  \"hasDigitalSignature\": " << (hasDigitalSignature ? "true" : "false") << ",\n";
    j << "  \"hasOverlay\": " << (hasOverlay ? "true" : "false") << ",\n";
    j << "  \"findings\": [\n";
    for (size_t i = 0; i < findings.size(); ++i)
    {
        j << "    {\n";
        j << "      \"weight\": " << findings[i].weight << ",\n";
        j << "      \"category\": \"" << escapeJson(findings[i].category) << "\",\n";
        j << "      \"detail\": \"" << escapeJson(findings[i].detail) << "\",\n";
        j << "      \"mitreId\": \"" << escapeJson(findings[i].mitreId) << "\",\n";
        j << "      \"mitreTactic\": \"" << escapeJson(findings[i].mitreTactic) << "\"\n";
        j << "    }" << (i + 1 < findings.size() ? "," : "") << "\n";
    }
    j << "  ]\n";
    j << "}\n";
    return j.str();
}

std::string AnalysisResult::generateHtmlReport() const
{
    std::ostringstream h;
    h << "<!DOCTYPE html>\n<html lang=\"tr\">\n<head>\n";
    h << "<meta charset=\"UTF-8\">\n<title>BinaryAnalyzer Raporu - " << fileName << "</title>\n";
    h << "<style>\n";
    h << "  body { background-color: #121214; color: #e4e4e7; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 30px; line-height: 1.6; }\n";
    h << "  .container { max-width: 1150px; margin: 0 auto; }\n";
    h << "  .card { background-color: #18181b; border: 1px solid #27272a; border-radius: 8px; padding: 20px; margin-bottom: 25px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5); }\n";
    h << "  h1, h2, h3 { color: #fafafa; margin-top: 0; }\n";
    h << "  .badge { display: inline-block; padding: 6px 14px; border-radius: 9999px; font-weight: bold; font-size: 14px; }\n";
    h << "  .badge-low { background-color: #14532d; color: #4ade80; }\n";
    h << "  .badge-med { background-color: #713f12; color: #facc15; }\n";
    h << "  .badge-high { background-color: #7f1d1d; color: #f87171; }\n";
    h << "  .badge-crit { background-color: #881337; color: #f43f5e; animation: pulse 2s infinite; }\n";
    h << "  .mitre-pill { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; background: #3b82f6; color: #fff; margin-right: 6px; }\n";
    h << "  table { width: 100%; border-collapse: collapse; margin-top: 15px; }\n";
    h << "  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #27272a; font-size: 14px; }\n";
    h << "  th { background-color: #27272a; color: #a1a1aa; font-weight: 600; }\n";
    h << "  tr:hover { background-color: #202024; }\n";
    h << "  .code { font-family: 'Consolas', 'Courier New', monospace; color: #38bdf8; }\n";
    h << "  pre { background: #09090b; padding: 14px; border-radius: 6px; font-family: 'Consolas', monospace; color: #a1a1aa; overflow-x: auto; border: 1px solid #27272a; }\n";
    h << "</style>\n</head>\n<body>\n<div class=\"container\">\n";
    h << "  <div class=\"card\">\n";
    h << "    <h1>🛡️ BinaryAnalyzer v2.0 - Statik Analiz Raporu</h1>\n";
    h << "    <p><strong>Dosya:</strong> " << fileName << " (" << formattedSize << ") | <strong>Format:</strong> " << formatName << " | <strong>Derleyici:</strong> " << compilerDetected << "</p>\n";
    h << "    <span class=\"badge " << (riskScore <= 20 ? "badge-low" : (riskScore <= 50 ? "badge-med" : (riskScore <= 80 ? "badge-high" : "badge-crit"))) << "\">\n";
    h << "      RİSK: " << riskLevel << " (" << riskScore << " Puan)\n";
    h << "    </span>\n";
    h << "  </div>\n";

    h << "  <div class=\"card\">\n";
    h << "    <h2>🔑 Kriptografik Parmak İzleri (Hashes)</h2>\n";
    h << "    <p><strong>MD5:</strong> <span class=\"code\">" << md5 << "</span></p>\n";
    h << "    <p><strong>SHA-1:</strong> <span class=\"code\">" << sha1 << "</span></p>\n";
    h << "    <p><strong>SHA-256:</strong> <span class=\"code\">" << sha256 << "</span></p>\n";
    if (!imphash.empty()) {
        h << "    <p><strong>Import Hash (Imphash):</strong> <span class=\"code\">" << imphash << "</span></p>\n";
    }
    h << "    <p><strong>Genel Shannon Entropisi:</strong> " << overallEntropy << " / 8.0000</p>\n";
    h << "  </div>\n";

    h << "  <div class=\"card\">\n";
    h << "    <h2>⚠️ Tespit Edilen Tehdit Bulguları & MITRE ATT&CK(R)</h2>\n";
    h << "    <table>\n";
    h << "      <thead><tr><th>Ağırlık</th><th>Kategori</th><th>Açıklama</th><th>MITRE ATT&CK</th></tr></thead>\n";
    h << "      <tbody>\n";
    for (const auto& f : findings)
    {
        h << "        <tr><td style=\"color:#f87171;\">+" << f.weight << "</td><td>" << f.category << "</td><td>" << f.detail << "</td>";
        h << "<td>";
        if (!f.mitreId.empty() && f.mitreId != "-") {
            h << "<span class=\"mitre-pill\">" << f.mitreId << "</span> " << f.mitreTactic;
        } else {
            h << "-";
        }
        h << "</td></tr>\n";
    }
    h << "      </tbody>\n    </table>\n  </div>\n";

    if (!entryPointHexDump.empty()) {
        h << "  <div class=\"card\">\n";
        h << "    <h2>🔍 Entry Point Hex & Disassembly Görünümü</h2>\n";
        h << "    <pre>" << entryPointHexDump << "</pre>\n";
        h << "  </div>\n";
    }

    h << "</div>\n</body>\n</html>\n";
    return h.str();
}
