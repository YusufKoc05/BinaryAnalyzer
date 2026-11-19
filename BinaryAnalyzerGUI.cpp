#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <dwmapi.h>

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#include "AnalyzerEngine.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "dwmapi.lib")

// DWM Dark Mode sabiti (Windows 10 build 18985+ / Windows 11)
#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

// Kontrol Tanımlayıcıları
#define IDC_BTN_BROWSE        1001
#define IDC_BTN_ANALYZE       1002
#define IDC_BTN_SAVE_REPORT   1003
#define IDC_BTN_COPY_REPORT   1004
#define IDC_BTN_VIRUSTOTAL    1005
#define IDC_EDIT_FILEPATH     1006
#define IDC_TAB_MAIN          1007

#define IDC_LIST_SECTIONS     1010
#define IDC_LIST_IMPORTS      1011
#define IDC_LIST_THREATS      1012
#define IDC_LIST_STRINGS      1013
#define IDC_EDIT_SUMMARY      1014
#define IDC_EDIT_HEX          1015
#define IDC_EDIT_FULL_REPORT  1016

namespace
{
    HINSTANCE g_hInstance = nullptr;
    HWND g_hWndMain = nullptr;
    HWND g_hEditPath = nullptr;
    HWND g_hBtnBrowse = nullptr;
    HWND g_hBtnAnalyze = nullptr;
    HWND g_hBtnSave = nullptr;
    HWND g_hBtnCopy = nullptr;
    HWND g_hBtnVirusTotal = nullptr;
    HWND g_hTab = nullptr;

    HWND g_hEditSummary = nullptr;
    HWND g_hListSections = nullptr;
    HWND g_hListImports = nullptr;
    HWND g_hListThreats = nullptr;
    HWND g_hListStrings = nullptr;
    HWND g_hEditHex = nullptr;
    HWND g_hEditFullReport = nullptr;

    HWND g_hLblStatus = nullptr;
    HWND g_hLblRiskBadge = nullptr;

    HFONT g_hFontNormal = nullptr;
    HFONT g_hFontBold = nullptr;
    HFONT g_hFontCode = nullptr;
    HFONT g_hFontTitle = nullptr;

    // Siyah / Gri / Beyaz Renk Paleti (Dark Theme)
    const COLORREF CLR_MAIN_BG   = RGB(18, 18, 22);      // Koyu Siyah Arka Plan
    const COLORREF CLR_CARD_BG   = RGB(26, 26, 32);      // Koyu Gri Kart Arka Planı
    const COLORREF CLR_INPUT_BG  = RGB(22, 22, 28);      // Input/Kutu Arka Planı
    const COLORREF CLR_BORDER    = RGB(48, 48, 58);      // Kenarlık Grisi
    const COLORREF CLR_TEXT_W    = RGB(245, 245, 250);   // Parlak Beyaz Metin
    const COLORREF CLR_TEXT_GRAY = RGB(150, 155, 165);   // Yumuşak Gri Metin
    const COLORREF CLR_BTN_BG    = RGB(36, 36, 46);      // Düğme Grisi
    const COLORREF CLR_BTN_HOVER = RGB(50, 50, 64);      // Düğme Üzerine Gelme

    HBRUSH g_hbrMainBg = nullptr;
    HBRUSH g_hbrCardBg = nullptr;
    HBRUSH g_hbrInputBg = nullptr;
    HBRUSH g_hbrBtnBg = nullptr;
    HBRUSH g_hbrRiskBadge = nullptr;

    COLORREF g_clrRiskText = RGB(245, 245, 250);
    COLORREF g_clrRiskBg = RGB(36, 36, 46);

    AnalysisResult g_currentResult;

    std::wstring toWString(const std::string& str)
    {
        if (str.empty()) return L"";
        int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
        std::wstring wstr(sizeNeeded, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], sizeNeeded);
        if (!wstr.empty() && wstr.back() == L'\0') wstr.pop_back();
        return wstr;
    }

    std::string toString(const std::wstring& wstr)
    {
        if (wstr.empty()) return "";
        int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string str(sizeNeeded, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], sizeNeeded, nullptr, nullptr);
        if (!str.empty() && str.back() == '\0') str.pop_back();
        return str;
    }

    void setStatus(const std::wstring& text)
    {
        if (g_hLblStatus)
        {
            SetWindowTextW(g_hLblStatus, text.c_str());
        }
    }

    void switchTab(int tabIndex)
    {
        ShowWindow(g_hEditSummary,    (tabIndex == 0) ? SW_SHOW : SW_HIDE);
        ShowWindow(g_hListSections,   (tabIndex == 1) ? SW_SHOW : SW_HIDE);
        ShowWindow(g_hListImports,    (tabIndex == 2) ? SW_SHOW : SW_HIDE);
        ShowWindow(g_hListThreats,    (tabIndex == 3) ? SW_SHOW : SW_HIDE);
        ShowWindow(g_hListStrings,    (tabIndex == 4) ? SW_SHOW : SW_HIDE);
        ShowWindow(g_hEditHex,        (tabIndex == 5) ? SW_SHOW : SW_HIDE);
        ShowWindow(g_hEditFullReport, (tabIndex == 6) ? SW_SHOW : SW_HIDE);
        ShowWindow(g_hBtnCopy,        (tabIndex == 6) ? SW_SHOW : SW_HIDE);
    }

    void updateGUIWithResult(const AnalysisResult& res)
    {
        if (!res.success)
        {
            SetWindowTextW(g_hLblRiskBadge, L"ANALİZ HATASI");
            std::wstring err = L"Hata: " + toWString(res.errorMessage);
            setStatus(err);
            MessageBoxW(g_hWndMain, err.c_str(), L"Hata", MB_ICONERROR);
            return;
        }

        // Risk Rozetinin Renklerini Ayarlama
        if (res.riskScore <= 20)
        {
            g_clrRiskBg = RGB(22, 65, 35);
            g_clrRiskText = RGB(74, 222, 128);
        }
        else if (res.riskScore <= 50)
        {
            g_clrRiskBg = RGB(95, 60, 15);
            g_clrRiskText = RGB(250, 204, 21);
        }
        else if (res.riskScore <= 80)
        {
            g_clrRiskBg = RGB(110, 25, 30);
            g_clrRiskText = RGB(248, 113, 113);
        }
        else
        {
            g_clrRiskBg = RGB(140, 15, 40);
            g_clrRiskText = RGB(255, 255, 255);
        }

        if (g_hbrRiskBadge) DeleteObject(g_hbrRiskBadge);
        g_hbrRiskBadge = CreateSolidBrush(g_clrRiskBg);

        std::wstring riskText = L"RİSK: " + toWString(res.riskLevel) + L" [" + std::to_wstring(res.riskScore) + L" PUAN]";
        SetWindowTextW(g_hLblRiskBadge, riskText.c_str());
        InvalidateRect(g_hLblRiskBadge, nullptr, TRUE);

        std::wstring statusStr = L"Analiz Tamamlandı: " + toWString(res.fileName) + L" | Boyut: " + toWString(res.formattedSize) +
                                 L" | Biçim: " + toWString(res.formatName);
        setStatus(statusStr);

        // 1. Sekme: Genel Bakış & Header
        std::wostringstream summary;
        summary << L"┌────────────────────────────────────────────────────────────────────────┐\r\n";
        summary << L"│                    DOSYA PARMAK İZLERİ (HASHES)                        │\r\n";
        summary << L"└────────────────────────────────────────────────────────────────────────┘\r\n";
        summary << L"  Dosya Adı       : " << toWString(res.fileName) << L"\r\n";
        summary << L"  Dosya Yolu      : " << toWString(res.filePath) << L"\r\n";
        summary << L"  Dosya Boyutu    : " << toWString(res.formattedSize) << L"\r\n";
        summary << L"  MD5             : " << toWString(res.md5) << L"\r\n";
        summary << L"  SHA-1           : " << toWString(res.sha1) << L"\r\n";
        summary << L"  SHA-256         : " << toWString(res.sha256) << L"\r\n";
        if (!res.imphash.empty())
        {
            summary << L"  Import Hash     : " << toWString(res.imphash) << L"  (Mandiant / VirusTotal Imphash Standardı)\r\n";
        }
        summary << L"  Genel Entropi   : " << std::fixed << std::setprecision(4) << res.overallEntropy << L" / 8.0000";
        if (res.isPackedOrEncrypted) summary << L"  [!! YÜKSEK ENTROPİ / PACKED ŞÜPHESİ !!]";
        summary << L"\r\n\r\n";

        summary << L"┌────────────────────────────────────────────────────────────────────────┐\r\n";
        summary << L"│                BİÇİM, DERLEYİCİ & HEADER TERSİNE MÜHENDİSLİK           │\r\n";
        summary << L"└────────────────────────────────────────────────────────────────────────┘\r\n";
        summary << L"  Format          : " << toWString(res.formatName) << L"\r\n";
        summary << L"  Mimari          : " << toWString(res.architecture) << L"\r\n";
        summary << L"  Subsystem       : " << toWString(res.subsystem) << L"\r\n";
        if (!res.compilerDetected.empty()) summary << L"  Derleyici/Araç  : " << toWString(res.compilerDetected) << L"\r\n";
        if (res.isDotNet) summary << L"  Yönetilen Kod   : .NET CLR Runtime VAR\r\n";
        if (!res.compileTime.empty()) summary << L"  Derleme Zamanı  : " << toWString(res.compileTime) << L"\r\n";
        summary << L"  Entry Point RVA : 0x" << std::hex << res.entryPoint << std::dec << L"\r\n";
        if (!res.entryPointPrologue.empty()) summary << L"  EP Analizi      : " << toWString(res.entryPointPrologue) << L"\r\n";
        summary << L"  TLS Callback    : " << (res.hasTls ? (L"VAR (" + std::to_wstring(res.tlsCallbacksCount) + L" adet callback)") : L"Yok") << L"\r\n";
        summary << L"  Dijital İmza    : " << (res.hasDigitalSignature ? (L"MEVCUT (" + std::to_wstring(res.signatureSize) + L" Byte)") : L"Yok / İmzasız") << L"\r\n";
        summary << L"  Overlay Verisi  : " << (res.hasOverlay ? (L"TESPİT EDİLDİ (" + toWString(std::to_string(res.overlaySize)) + L" Byte ek veri)") : L"Temiz (Yok)") << L"\r\n\r\n";

        if (res.formatName.find("PE") != std::string::npos)
        {
            summary << L"┌────────────────────────────────────────────────────────────────────────┐\r\n";
            summary << L"│                EXPLOIT SAVUNMA MEKANİZMALARI (MITIGATIONS)             │\r\n";
            summary << L"└────────────────────────────────────────────────────────────────────────┘\r\n";
            summary << L"  [ " << (res.mitigations.hasASLR ? L"AKTİF" : L"KAPALI - RİSKLİ") << L" ] ASLR (Address Space Layout Randomization)\r\n";
            summary << L"  [ " << (res.mitigations.hasDEP ? L"AKTİF" : L"KAPALI - RİSKLİ") << L" ] DEP / NX (Data Execution Prevention)\r\n";
            summary << L"  [ " << (res.mitigations.hasCFG ? L"AKTİF" : L"KAPALI") << L" ] Control Flow Guard (CFG)\r\n";
            summary << L"  [ " << (res.mitigations.hasSEH ? L"AKTİF" : L"DEVRE DIŞI") << L" ] Structured Exception Handling (SEH)\r\n";
        }
        else
        {
            summary << L"┌────────────────────────────────────────────────────────────────────────┐\r\n";
            summary << L"│                         LİNUX GÜVENLİK ANALİZİ                         │\r\n";
            summary << L"└────────────────────────────────────────────────────────────────────────┘\r\n";
            summary << L"  [ " << (res.elfExecutableStack ? L"TEHLİKELİ - STACK EXEC" : L"GÜVENLİ - NX AKTİF") << L" ] Executable Stack (PT_GNU_STACK)\r\n";
        }

        SetWindowTextW(g_hEditSummary, summary.str().c_str());

        // 2. Sekme: Sections Listesi
        ListView_DeleteAllItems(g_hListSections);
        int itemIndex = 0;
        if (!res.peSections.empty())
        {
            for (const auto& sec : res.peSections)
            {
                LVITEMW item{};
                item.mask = LVIF_TEXT;
                item.iItem = itemIndex;

                std::wstring name = toWString(sec.name);
                item.pszText = &name[0];
                ListView_InsertItem(g_hListSections, &item);

                std::wostringstream ssVA, ssVS, ssRS, ssEnt;
                ssVA << L"0x" << std::hex << sec.virtualAddress;
                ssVS << L"0x" << std::hex << sec.virtualSize;
                ssRS << L"0x" << std::hex << sec.rawSize;
                ssEnt << std::fixed << std::setprecision(2) << sec.entropy;

                std::wstring perms;
                if (sec.isReadable) perms += L"R";
                if (sec.isWritable) perms += L"W";
                if (sec.isExecutable) perms += L"X";

                std::wstring status = L"Normal";
                if (sec.isRWX) status = L"!! RWX (ŞÜPHELİ) !!";
                else if (sec.entropy > 7.1) status = L"* Yüksek Entropi (Packed?) *";

                ListView_SetItemText(g_hListSections, itemIndex, 1, (LPWSTR)ssVA.str().c_str());
                ListView_SetItemText(g_hListSections, itemIndex, 2, (LPWSTR)ssVS.str().c_str());
                ListView_SetItemText(g_hListSections, itemIndex, 3, (LPWSTR)ssRS.str().c_str());
                ListView_SetItemText(g_hListSections, itemIndex, 4, (LPWSTR)ssEnt.str().c_str());
                ListView_SetItemText(g_hListSections, itemIndex, 5, (LPWSTR)perms.c_str());
                ListView_SetItemText(g_hListSections, itemIndex, 6, (LPWSTR)status.c_str());

                itemIndex++;
            }
        }
        else if (!res.elfSections.empty())
        {
            for (const auto& sec : res.elfSections)
            {
                if (sec.name.empty()) continue;
                LVITEMW item{};
                item.mask = LVIF_TEXT;
                item.iItem = itemIndex;

                std::wstring name = toWString(sec.name);
                item.pszText = &name[0];
                ListView_InsertItem(g_hListSections, &item);

                std::wostringstream ssAddr, ssSize, ssEnt;
                ssAddr << L"0x" << std::hex << sec.addr;
                ssSize << L"0x" << std::hex << sec.size;
                ssEnt << std::fixed << std::setprecision(2) << sec.entropy;

                std::wstring perms;
                if (sec.isAlloc) perms += L"A";
                if (sec.isWritable) perms += L"W";
                if (sec.isExecutable) perms += L"X";

                std::wstring status = L"Normal";
                if (sec.isRWX) status = L"!! RWX (ŞÜPHELİ) !!";
                else if (sec.entropy > 7.1) status = L"* Yüksek Entropi *";

                ListView_SetItemText(g_hListSections, itemIndex, 1, (LPWSTR)ssAddr.str().c_str());
                ListView_SetItemText(g_hListSections, itemIndex, 2, (LPWSTR)ssSize.str().c_str());
                ListView_SetItemText(g_hListSections, itemIndex, 3, (LPWSTR)ssSize.str().c_str());
                ListView_SetItemText(g_hListSections, itemIndex, 4, (LPWSTR)ssEnt.str().c_str());
                ListView_SetItemText(g_hListSections, itemIndex, 5, (LPWSTR)perms.c_str());
                ListView_SetItemText(g_hListSections, itemIndex, 6, (LPWSTR)status.c_str());

                itemIndex++;
            }
        }

        // 3. Sekme: Importlar & Exportlar
        ListView_DeleteAllItems(g_hListImports);
        int impIndex = 0;
        for (const auto& expFunc : res.exportedFunctions)
        {
            LVITEMW item{};
            item.mask = LVIF_TEXT;
            item.iItem = impIndex;
            std::wstring eName = toWString(expFunc);
            item.pszText = &eName[0];
            ListView_InsertItem(g_hListImports, &item);
            ListView_SetItemText(g_hListImports, impIndex, 1, (LPWSTR)L"Dışa Aktarılan Fonksiyon (EXPORT)");
            impIndex++;
        }
        for (const auto& dll : res.importedDlls)
        {
            LVITEMW item{};
            item.mask = LVIF_TEXT;
            item.iItem = impIndex;
            std::wstring dName = toWString(dll);
            item.pszText = &dName[0];
            ListView_InsertItem(g_hListImports, &item);
            ListView_SetItemText(g_hListImports, impIndex, 1, (LPWSTR)L"Dinamik Kütüphane (IMPORT DLL)");
            impIndex++;
        }
        for (const auto& func : res.importedFunctions)
        {
            LVITEMW item{};
            item.mask = LVIF_TEXT;
            item.iItem = impIndex;
            std::wstring fName = toWString(func);
            item.pszText = &fName[0];
            ListView_InsertItem(g_hListImports, &item);
            ListView_SetItemText(g_hListImports, impIndex, 1, (LPWSTR)L"Windows API Fonksiyonu (IMPORT)");
            impIndex++;
        }

        // 4. Sekme: Tehdit & Malware Bulguları (MITRE ATT&CK)
        ListView_DeleteAllItems(g_hListThreats);
        int thIndex = 0;
        for (const auto& f : res.findings)
        {
            LVITEMW item{};
            item.mask = LVIF_TEXT;
            item.iItem = thIndex;

            std::wstring pScore = L"+" + std::to_wstring(f.weight);
            item.pszText = &pScore[0];
            ListView_InsertItem(g_hListThreats, &item);

            std::wstring cat = toWString(f.category);
            std::wstring mId = toWString(f.mitreId);
            std::wstring mTact = toWString(f.mitreTactic);
            std::wstring det = toWString(f.detail);

            ListView_SetItemText(g_hListThreats, thIndex, 1, (LPWSTR)cat.c_str());
            ListView_SetItemText(g_hListThreats, thIndex, 2, (LPWSTR)mId.c_str());
            ListView_SetItemText(g_hListThreats, thIndex, 3, (LPWSTR)mTact.c_str());
            ListView_SetItemText(g_hListThreats, thIndex, 4, (LPWSTR)det.c_str());

            thIndex++;
        }

        // 5. Sekme: Stringler & IOC Taraması
        ListView_DeleteAllItems(g_hListStrings);
        int strIndex = 0;
        // Önce bulunan IOC'leri (URL, IP, Komut) en başa ekleyelim
        for (const auto& url : res.detectedIocUrls)
        {
            LVITEMW item{};
            item.mask = LVIF_TEXT;
            item.iItem = strIndex;
            std::wstring uStr = toWString(url);
            item.pszText = &uStr[0];
            ListView_InsertItem(g_hListStrings, &item);
            ListView_SetItemText(g_hListStrings, strIndex, 1, (LPWSTR)L"AĞ / URL GÖSTERGESİ (IOC)");
            ListView_SetItemText(g_hListStrings, strIndex, 2, (LPWSTR)L"Şüpheli Bağlantı");
            strIndex++;
        }
        for (const auto& cmd : res.detectedIocCommands)
        {
            LVITEMW item{};
            item.mask = LVIF_TEXT;
            item.iItem = strIndex;
            std::wstring cStr = toWString(cmd);
            item.pszText = &cStr[0];
            ListView_InsertItem(g_hListStrings, &item);
            ListView_SetItemText(g_hListStrings, strIndex, 1, (LPWSTR)L"KOMUT SATIRI GÖSTERGESİ (IOC)");
            ListView_SetItemText(g_hListStrings, strIndex, 2, (LPWSTR)L"Sistem Aracı Çağrısı");
            strIndex++;
        }
        // Genel metin dizilerini ekleyelim (ilk 1000)
        for (size_t i = 0; i < res.extractedStrings.size() && strIndex < 1200; ++i)
        {
            const auto& es = res.extractedStrings[i];
            LVITEMW item{};
            item.mask = LVIF_TEXT;
            item.iItem = strIndex;
            std::wstring sVal = toWString(es.value);
            item.pszText = &sVal[0];
            ListView_InsertItem(g_hListStrings, &item);

            std::wstring typeStr = es.isUnicode ? L"Unicode (UTF-16LE)" : L"ASCII";
            ListView_SetItemText(g_hListStrings, strIndex, 1, (LPWSTR)typeStr.c_str());

            std::wostringstream ssOff;
            ssOff << L"0x" << std::hex << es.offset;
            ListView_SetItemText(g_hListStrings, strIndex, 2, (LPWSTR)ssOff.str().c_str());

            strIndex++;
        }

        // 6. Sekme: Entry Point Hex & Disassembly Görünümü
        std::wostringstream hexReport;
        hexReport << L"┌────────────────────────────────────────────────────────────────────────┐\r\n";
        hexReport << L"│           ENTRY POINT (RVA: 0x" << std::hex << res.entryPoint << std::dec << L") OPCODES & HEX INSPECTOR               │\r\n";
        hexReport << L"└────────────────────────────────────────────────────────────────────────┘\r\n";
        hexReport << L"  Analiz Edilen Fonksiyon Giriş Paterni (Prologue):\r\n";
        hexReport << L"  >> " << toWString(res.entryPointPrologue) << L"\r\n\r\n";
        hexReport << L"  İlk 64 Bayt Makine Kodu / Bellek Dökümü (Address | Hex Bytes | ASCII):\r\n";
        hexReport << L"  ────────────────────────────────────────────────────────────────────────\r\n";
        hexReport << toWString(res.entryPointHexDump);
        SetWindowTextW(g_hEditHex, hexReport.str().c_str());

        // 7. Sekme: Ham Metin Raporu
        SetWindowTextW(g_hEditFullReport, toWString(res.fullReportText).c_str());
    }

    void analyzeFile(const std::wstring& wFilePath)
    {
        if (wFilePath.empty()) return;
        SetWindowTextW(g_hEditPath, wFilePath.c_str());
        setStatus(L"Analiz ediliyor, lütfen bekleyin...");

        std::string path = toString(wFilePath);
        g_currentResult = AnalyzerEngine::analyze(path);
        updateGUIWithResult(g_currentResult);
    }

    void onBrowseFile()
    {
        wchar_t szFile[MAX_PATH] = {0};
        OPENFILENAMEW ofn{};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_hWndMain;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);
        ofn.lpstrFilter = L"Tüm Çalıştırılabilir Dosyalar (*.exe;*.dll;*.sys;*.bin;*.elf)\0*.exe;*.dll;*.sys;*.bin;*.elf\0Tüm Dosyalar (*.*)\0*.*\0";
        ofn.nFilterIndex = 1;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

        if (GetOpenFileNameW(&ofn))
        {
            analyzeFile(szFile);
        }
    }

    void onVirusTotalLookup()
    {
        if (!g_currentResult.success || g_currentResult.sha256.empty())
        {
            MessageBoxW(g_hWndMain, L"Önce geçerli bir dosya analiz edin.", L"Bilgi", MB_ICONINFORMATION);
            return;
        }

        std::wstring url = L"https://www.virustotal.com/gui/file/" + toWString(g_currentResult.sha256);
        ShellExecuteW(nullptr, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    }

    void onSaveReport()
    {
        if (!g_currentResult.success)
        {
            MessageBoxW(g_hWndMain, L"Kaydedilecek analiz raporu bulunamadı. Önce bir dosya analiz edin.", L"Uyarı", MB_ICONWARNING);
            return;
        }

        wchar_t szFile[MAX_PATH] = {0};
        std::wstring defaultName = toWString(g_currentResult.fileName) + L"_Rapor";
        wcsncpy_s(szFile, defaultName.c_str(), _TRUNCATE);

        OPENFILENAMEW ofn{};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_hWndMain;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);
        ofn.lpstrFilter = L"Metin Raporu (*.txt)\0*.txt\0Görsel HTML Raporu (*.html)\0*.html\0JSON Verisi (*.json)\0*.json\0";
        ofn.nFilterIndex = 1;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

        if (GetSaveFileNameW(&ofn))
        {
            std::string contentToSave;
            if (ofn.nFilterIndex == 2)
            {
                contentToSave = g_currentResult.generateHtmlReport();
            }
            else if (ofn.nFilterIndex == 3)
            {
                contentToSave = g_currentResult.generateJsonReport();
            }
            else
            {
                contentToSave = g_currentResult.fullReportText;
            }

            HANDLE hFile = CreateFileW(szFile, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile != INVALID_HANDLE_VALUE)
            {
                DWORD bytesWritten = 0;
                WriteFile(hFile, contentToSave.c_str(), (DWORD)contentToSave.size(), &bytesWritten, nullptr);
                CloseHandle(hFile);
                MessageBoxW(g_hWndMain, L"Rapor başarıyla kaydedildi!", L"Başarılı", MB_ICONINFORMATION);
            }
        }
    }

    void onCopyReport()
    {
        if (g_currentResult.fullReportText.empty()) return;

        if (OpenClipboard(g_hWndMain))
        {
            EmptyClipboard();
            std::wstring wText = toWString(g_currentResult.fullReportText);
            size_t bytes = (wText.size() + 1) * sizeof(wchar_t);
            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
            if (hMem)
            {
                memcpy(GlobalLock(hMem), wText.c_str(), bytes);
                GlobalUnlock(hMem);
                SetClipboardData(CF_UNICODETEXT, hMem);
            }
            CloseClipboard();
            MessageBoxW(g_hWndMain, L"Analiz raporu panoya kopyalandı!", L"Kopyalandı", MB_ICONINFORMATION);
        }
    }

    void drawModernButton(LPDRAWITEMSTRUCT pDIS, const wchar_t* text)
    {
        HDC hdc = pDIS->hDC;
        RECT rect = pDIS->rcItem;
        bool isPressed = (pDIS->itemState & ODS_SELECTED);

        // Arka plan
        COLORREF bg = isPressed ? RGB(60, 60, 75) : CLR_BTN_BG;
        HBRUSH hbr = CreateSolidBrush(bg);
        FillRect(hdc, &rect, hbr);
        DeleteObject(hbr);

        // Kenarlık
        HPEN hPen = CreatePen(PS_SOLID, 1, isPressed ? RGB(100, 100, 120) : CLR_BORDER);
        HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
        SelectObject(hdc, GetStockObject(NULL_BRUSH));
        RoundRect(hdc, rect.left, rect.top, rect.right, rect.bottom, 4, 4);
        SelectObject(hdc, hOldPen);
        DeleteObject(hPen);

        // Metin
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, CLR_TEXT_W);
        SelectObject(hdc, g_hFontNormal);
        DrawTextW(hdc, text, -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }

    void initControls(HWND hWnd)
    {
        // Dark Brushes
        g_hbrMainBg = CreateSolidBrush(CLR_MAIN_BG);
        g_hbrCardBg = CreateSolidBrush(CLR_CARD_BG);
        g_hbrInputBg = CreateSolidBrush(CLR_INPUT_BG);
        g_hbrBtnBg = CreateSolidBrush(CLR_BTN_BG);
        g_hbrRiskBadge = CreateSolidBrush(g_clrRiskBg);

        // Fontlar (Segoe UI & Consolas)
        g_hFontNormal = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g_hFontBold   = CreateFontW(16, 0, 0, 0, FW_BOLD,   FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g_hFontTitle  = CreateFontW(18, 0, 0, 0, FW_BOLD,   FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g_hFontCode   = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_DONTCARE, L"Consolas");

        // Üst Bar: Dosya Seçimi
        CreateWindowW(L"STATIC", L"Analiz Edilecek Dosya:", WS_CHILD | WS_VISIBLE, 15, 16, 155, 20, hWnd, nullptr, g_hInstance, nullptr);

        g_hEditPath = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY | WS_BORDER,
            175, 12, 450, 26, hWnd, (HMENU)IDC_EDIT_FILEPATH, g_hInstance, nullptr);

        g_hBtnBrowse = CreateWindowW(L"BUTTON", L"Dosya Seç...", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            635, 11, 105, 28, hWnd, (HMENU)IDC_BTN_BROWSE, g_hInstance, nullptr);

        g_hBtnAnalyze = CreateWindowW(L"BUTTON", L"Yeniden Analiz Et", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            750, 11, 125, 28, hWnd, (HMENU)IDC_BTN_ANALYZE, g_hInstance, nullptr);

        g_hBtnVirusTotal = CreateWindowW(L"BUTTON", L"VirusTotal'da Ara", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            885, 11, 125, 28, hWnd, (HMENU)IDC_BTN_VIRUSTOTAL, g_hInstance, nullptr);

        g_hBtnSave = CreateWindowW(L"BUTTON", L"Raporu Kaydet...", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            1020, 11, 125, 28, hWnd, (HMENU)IDC_BTN_SAVE_REPORT, g_hInstance, nullptr);

        // Risk Rozeti & Durum Çubuğu
        g_hLblRiskBadge = CreateWindowW(L"STATIC", L"RİSK: HENÜZ ANALİZ EDİLMEDİ", WS_CHILD | WS_VISIBLE | SS_CENTER | SS_CENTERIMAGE | WS_BORDER,
            15, 48, 310, 30, hWnd, nullptr, g_hInstance, nullptr);

        g_hLblStatus = CreateWindowW(L"STATIC", L"Hazır. Lütfen bir dosya seçin veya bu pencereye sürükleyip bırakın.", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
            335, 52, 800, 24, hWnd, nullptr, g_hInstance, nullptr);

        // Tab Control
        g_hTab = CreateWindowExW(0, WC_TABCONTROLW, L"", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
            15, 88, 1130, 600, hWnd, (HMENU)IDC_TAB_MAIN, g_hInstance, nullptr);

        TCITEMW tie{};
        tie.mask = TCIF_TEXT;

        wchar_t tab1[] = L"  📊 Genel Bakış & Header  "; tie.pszText = tab1; TabCtrl_InsertItem(g_hTab, 0, &tie);
        wchar_t tab2[] = L"  📑 Bölümler (Sections)  "; tie.pszText = tab2; TabCtrl_InsertItem(g_hTab, 1, &tie);
        wchar_t tab3[] = L"  🔗 Import & Exportlar  "; tie.pszText = tab3; TabCtrl_InsertItem(g_hTab, 2, &tie);
        wchar_t tab4[] = L"  🛡️ Tehditler (MITRE ATT&CK)  "; tie.pszText = tab4; TabCtrl_InsertItem(g_hTab, 3, &tie);
        wchar_t tab5[] = L"  🔍 Stringler & IOC Taraması  "; tie.pszText = tab5; TabCtrl_InsertItem(g_hTab, 4, &tie);
        wchar_t tab6[] = L"  🔬 Hex & Opcode Inspector  "; tie.pszText = tab6; TabCtrl_InsertItem(g_hTab, 5, &tie);
        wchar_t tab7[] = L"  📝 Ham Rapor  "; tie.pszText = tab7; TabCtrl_InsertItem(g_hTab, 6, &tie);

        // Sekme 0: Genel Bakış (Karanlık Edit Box)
        g_hEditSummary = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_BORDER,
            25, 122, 1110, 555, hWnd, (HMENU)IDC_EDIT_SUMMARY, g_hInstance, nullptr);

        // Sekme 1: Bölümler Listesi (Karanlık ListView)
        g_hListSections = CreateWindowExW(0, WC_LISTVIEWW, L"",
            WS_CHILD | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
            25, 122, 1110, 555, hWnd, (HMENU)IDC_LIST_SECTIONS, g_hInstance, nullptr);
        ListView_SetExtendedListViewStyle(g_hListSections, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        ListView_SetBkColor(g_hListSections, CLR_CARD_BG);
        ListView_SetTextBkColor(g_hListSections, CLR_CARD_BG);
        ListView_SetTextColor(g_hListSections, CLR_TEXT_W);

        LVCOLUMNW lvc{};
        lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        lvc.pszText = (LPWSTR)L"Bölüm İsmi"; lvc.cx = 120; ListView_InsertColumn(g_hListSections, 0, &lvc);
        lvc.pszText = (LPWSTR)L"Sanal Adres (VA)"; lvc.cx = 140; ListView_InsertColumn(g_hListSections, 1, &lvc);
        lvc.pszText = (LPWSTR)L"Sanal Boyut"; lvc.cx = 130; ListView_InsertColumn(g_hListSections, 2, &lvc);
        lvc.pszText = (LPWSTR)L"Ham Boyut"; lvc.cx = 130; ListView_InsertColumn(g_hListSections, 3, &lvc);
        lvc.pszText = (LPWSTR)L"Entropi (0-8)"; lvc.cx = 120; ListView_InsertColumn(g_hListSections, 4, &lvc);
        lvc.pszText = (LPWSTR)L"İzinler"; lvc.cx = 100; ListView_InsertColumn(g_hListSections, 5, &lvc);
        lvc.pszText = (LPWSTR)L"Tehdit Durumu"; lvc.cx = 350; ListView_InsertColumn(g_hListSections, 6, &lvc);

        // Sekme 2: Import & Export Listesi
        g_hListImports = CreateWindowExW(0, WC_LISTVIEWW, L"",
            WS_CHILD | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
            25, 122, 1110, 555, hWnd, (HMENU)IDC_LIST_IMPORTS, g_hInstance, nullptr);
        ListView_SetExtendedListViewStyle(g_hListImports, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        ListView_SetBkColor(g_hListImports, CLR_CARD_BG);
        ListView_SetTextBkColor(g_hListImports, CLR_CARD_BG);
        ListView_SetTextColor(g_hListImports, CLR_TEXT_W);

        lvc.pszText = (LPWSTR)L"İsim (DLL / API Fonksiyonu / Export)"; lvc.cx = 640; ListView_InsertColumn(g_hListImports, 0, &lvc);
        lvc.pszText = (LPWSTR)L"Tür & Rol"; lvc.cx = 450; ListView_InsertColumn(g_hListImports, 1, &lvc);

        // Sekme 3: Tehditler Listesi (MITRE ATT&CK Formatı)
        g_hListThreats = CreateWindowExW(0, WC_LISTVIEWW, L"",
            WS_CHILD | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
            25, 122, 1110, 555, hWnd, (HMENU)IDC_LIST_THREATS, g_hInstance, nullptr);
        ListView_SetExtendedListViewStyle(g_hListThreats, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        ListView_SetBkColor(g_hListThreats, CLR_CARD_BG);
        ListView_SetTextBkColor(g_hListThreats, CLR_CARD_BG);
        ListView_SetTextColor(g_hListThreats, CLR_TEXT_W);

        lvc.pszText = (LPWSTR)L"Puan"; lvc.cx = 60; ListView_InsertColumn(g_hListThreats, 0, &lvc);
        lvc.pszText = (LPWSTR)L"Tehdit Kategorisi"; lvc.cx = 190; ListView_InsertColumn(g_hListThreats, 1, &lvc);
        lvc.pszText = (LPWSTR)L"MITRE ID"; lvc.cx = 100; ListView_InsertColumn(g_hListThreats, 2, &lvc);
        lvc.pszText = (LPWSTR)L"MITRE Taktik"; lvc.cx = 240; ListView_InsertColumn(g_hListThreats, 3, &lvc);
        lvc.pszText = (LPWSTR)L"Açıklama ve Tespit Edilen Gösterge"; lvc.cx = 500; ListView_InsertColumn(g_hListThreats, 4, &lvc);

        // Sekme 4: Stringler & IOC Listesi
        g_hListStrings = CreateWindowExW(0, WC_LISTVIEWW, L"",
            WS_CHILD | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
            25, 122, 1110, 555, hWnd, (HMENU)IDC_LIST_STRINGS, g_hInstance, nullptr);
        ListView_SetExtendedListViewStyle(g_hListStrings, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        ListView_SetBkColor(g_hListStrings, CLR_CARD_BG);
        ListView_SetTextBkColor(g_hListStrings, CLR_CARD_BG);
        ListView_SetTextColor(g_hListStrings, CLR_TEXT_W);

        lvc.pszText = (LPWSTR)L"Karakter Dizisi (String / IOC)"; lvc.cx = 640; ListView_InsertColumn(g_hListStrings, 0, &lvc);
        lvc.pszText = (LPWSTR)L"Tür (Kategori)"; lvc.cx = 280; ListView_InsertColumn(g_hListStrings, 1, &lvc);
        lvc.pszText = (LPWSTR)L"Konum / Ofset"; lvc.cx = 170; ListView_InsertColumn(g_hListStrings, 2, &lvc);

        // Sekme 5: Entry Point Hex & Disassembly Inspector
        g_hEditHex = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_BORDER,
            25, 122, 1110, 555, hWnd, (HMENU)IDC_EDIT_HEX, g_hInstance, nullptr);

        // Sekme 6: Ham Analiz Raporu
        g_hEditFullReport = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_BORDER,
            25, 122, 1110, 505, hWnd, (HMENU)IDC_EDIT_FULL_REPORT, g_hInstance, nullptr);

        g_hBtnCopy = CreateWindowW(L"BUTTON", L"Panoya Kopyala", WS_CHILD | BS_OWNERDRAW,
            980, 637, 155, 30, hWnd, (HMENU)IDC_BTN_COPY_REPORT, g_hInstance, nullptr);

        // Font Atamaları
        SendMessageW(g_hEditPath, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
        SendMessageW(g_hTab, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);
        SendMessageW(g_hLblRiskBadge, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);
        SendMessageW(g_hLblStatus, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

        SendMessageW(g_hEditSummary, WM_SETFONT, (WPARAM)g_hFontCode, TRUE);
        SendMessageW(g_hListSections, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
        SendMessageW(g_hListImports, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
        SendMessageW(g_hListThreats, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
        SendMessageW(g_hListStrings, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
        SendMessageW(g_hEditHex, WM_SETFONT, (WPARAM)g_hFontCode, TRUE);
        SendMessageW(g_hEditFullReport, WM_SETFONT, (WPARAM)g_hFontCode, TRUE);

        DragAcceptFiles(hWnd, TRUE);
        switchTab(0);
    }

    LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
    {
        switch (message)
        {
        case WM_CREATE:
            initControls(hWnd);
            break;

        case WM_DRAWITEM:
            {
                LPDRAWITEMSTRUCT pDIS = (LPDRAWITEMSTRUCT)lParam;
                switch (pDIS->CtlID)
                {
                case IDC_BTN_BROWSE:      drawModernButton(pDIS, L"Dosya Seç..."); return TRUE;
                case IDC_BTN_ANALYZE:     drawModernButton(pDIS, L"Yeniden Analiz"); return TRUE;
                case IDC_BTN_VIRUSTOTAL:  drawModernButton(pDIS, L"VirusTotal"); return TRUE;
                case IDC_BTN_SAVE_REPORT: drawModernButton(pDIS, L"Raporu Kaydet"); return TRUE;
                case IDC_BTN_COPY_REPORT: drawModernButton(pDIS, L"Panoya Kopyala"); return TRUE;
                }
            }
            break;

        case WM_CTLCOLOREDIT:
            {
                HDC hdc = (HDC)wParam;
                SetTextColor(hdc, CLR_TEXT_W);
                SetBkColor(hdc, CLR_INPUT_BG);
                return (LRESULT)g_hbrInputBg;
            }

        case WM_CTLCOLORSTATIC:
            {
                HDC hdc = (HDC)wParam;
                HWND hStatic = (HWND)lParam;

                if (hStatic == g_hLblRiskBadge)
                {
                    SetTextColor(hdc, g_clrRiskText);
                    SetBkColor(hdc, g_clrRiskBg);
                    return (LRESULT)g_hbrRiskBadge;
                }
                if (hStatic == g_hEditSummary || hStatic == g_hEditFullReport || hStatic == g_hEditHex)
                {
                    SetTextColor(hdc, CLR_TEXT_W);
                    SetBkColor(hdc, CLR_INPUT_BG);
                    return (LRESULT)g_hbrInputBg;
                }

                SetTextColor(hdc, CLR_TEXT_W);
                SetBkColor(hdc, CLR_MAIN_BG);
                return (LRESULT)g_hbrMainBg;
            }

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
            case IDC_BTN_BROWSE:
                onBrowseFile();
                break;

            case IDC_BTN_ANALYZE:
                {
                    wchar_t path[MAX_PATH] = {0};
                    GetWindowTextW(g_hEditPath, path, MAX_PATH);
                    if (wcslen(path) > 0) analyzeFile(path);
                    else onBrowseFile();
                }
                break;

            case IDC_BTN_VIRUSTOTAL:
                onVirusTotalLookup();
                break;

            case IDC_BTN_SAVE_REPORT:
                onSaveReport();
                break;

            case IDC_BTN_COPY_REPORT:
                onCopyReport();
                break;
            }
            break;

        case WM_NOTIFY:
            {
                LPNMHDR pnm = (LPNMHDR)lParam;
                if (pnm->idFrom == IDC_TAB_MAIN && pnm->code == TCN_SELCHANGE)
                {
                    int sel = TabCtrl_GetCurSel(g_hTab);
                    switchTab(sel);
                }
            }
            break;

        case WM_DROPFILES:
            {
                HDROP hDrop = (HDROP)wParam;
                wchar_t filePath[MAX_PATH] = {0};
                if (DragQueryFileW(hDrop, 0, filePath, MAX_PATH))
                {
                    analyzeFile(filePath);
                }
                DragFinish(hDrop);
            }
            break;

        case WM_DESTROY:
            if (g_hFontNormal) DeleteObject(g_hFontNormal);
            if (g_hFontBold)   DeleteObject(g_hFontBold);
            if (g_hFontCode)   DeleteObject(g_hFontCode);
            if (g_hFontTitle)  DeleteObject(g_hFontTitle);
            if (g_hbrMainBg)   DeleteObject(g_hbrMainBg);
            if (g_hbrCardBg)   DeleteObject(g_hbrCardBg);
            if (g_hbrInputBg)  DeleteObject(g_hbrInputBg);
            if (g_hbrBtnBg)    DeleteObject(g_hbrBtnBg);
            if (g_hbrRiskBadge)DeleteObject(g_hbrRiskBadge);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProcW(hWnd, message, wParam, lParam);
        }
        return 0;
    }
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR pCmdLine, int nCmdShow)
{
    g_hInstance = hInstance;

    INITCOMMONCONTROLSEX icex{};
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wcex{};
    wcex.cbSize = sizeof(WNDCLASSEXW);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIconW(nullptr, IDI_SHIELD);
    wcex.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wcex.hbrBackground = CreateSolidBrush(CLR_MAIN_BG);
    wcex.lpszClassName = L"BinaryAnalyzerDarkGUIClass";

    if (!RegisterClassExW(&wcex))
    {
        return 1;
    }

    g_hWndMain = CreateWindowW(
        L"BinaryAnalyzerDarkGUIClass",
        L"BinaryAnalyzer v2.0 - Statik Zararlı Yazılım & Binary Tehdit Analiz Aracı",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 1175, 740,
        nullptr, nullptr, hInstance, nullptr
    );

    if (!g_hWndMain)
    {
        return 1;
    }

    // Windows 10/11 Koyu Başlık Çubuğunu (Dark Title Bar) Aktif Et
    BOOL useDarkMode = TRUE;
    DwmSetWindowAttribute(g_hWndMain, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode, sizeof(useDarkMode));

    ShowWindow(g_hWndMain, nCmdShow);
    UpdateWindow(g_hWndMain);

    if (pCmdLine && wcslen(pCmdLine) > 0)
    {
        std::wstring arg = pCmdLine;
        if (arg.front() == L'"' && arg.back() == L'"')
        {
            arg = arg.substr(1, arg.size() - 2);
        }
        analyzeFile(arg);
    }
    else
    {
        analyzeFile(L"C:\\Windows\\System32\\notepad.exe");
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam;
}
