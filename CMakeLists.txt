cmake_minimum_required(VERSION 3.15)
project(BinaryAnalyzer VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Ortak Motor Dosyaları
set(ENGINE_SOURCES
    BinaryFile.cpp
    PEParser.cpp
    ELFParser.cpp
    MalwareAnalyzer.cpp
    AnalyzerEngine.cpp
)

set(ENGINE_HEADERS
    BinaryFile.h
    IParser.h
    PEParser.h
    ELFParser.h
    MalwareAnalyzer.h
    AnalyzerEngine.h
)

# 1. Konsol Uygulaması (CLI)
add_executable(BinaryAnalyzer
    BinaryAnalyzer.cpp
    ${ENGINE_SOURCES}
    ${ENGINE_HEADERS}
)

if(MSVC)
    target_compile_options(BinaryAnalyzer PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(BinaryAnalyzer PRIVATE -Wall -Wextra -pedantic)
endif()

# 2. Windows Masaüstü Grafik Arayüz Uygulaması (GUI)
if(WIN32)
    add_executable(BinaryAnalyzerGUI WIN32
        BinaryAnalyzerGUI.cpp
        ${ENGINE_SOURCES}
        ${ENGINE_HEADERS}
    )

    target_compile_options(BinaryAnalyzerGUI PRIVATE /W4 /permissive- /utf-8)
    target_link_libraries(BinaryAnalyzerGUI PRIVATE comctl32 shell32 comdlg32)
endif()
