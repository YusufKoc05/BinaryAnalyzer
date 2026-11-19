#include "BinaryFile.h"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <array>
#include <cstring>
#include <cctype>

// --- MD5, SHA-1 ve SHA-256 Dahili Kriptografik Gerçekleştirmeleri ---
namespace
{
    // ================= SHA-256 =================
    inline uint32_t rotr32(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    inline uint32_t choose(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }
    inline uint32_t majority(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }
    inline uint32_t sig0(uint32_t x) { return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22); }
    inline uint32_t sig1(uint32_t x) { return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25); }
    inline uint32_t theta0(uint32_t x) { return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3); }
    inline uint32_t theta1(uint32_t x) { return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10); }

    const uint32_t K256[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    std::string computeSha256(const uint8_t* data, size_t length)
    {
        uint32_t H[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        uint64_t totalBits = length * 8;
        size_t paddedLen = ((length + 8) / 64 + 1) * 64;
        std::vector<uint8_t> buffer(paddedLen, 0);
        std::memcpy(buffer.data(), data, length);
        buffer[length] = 0x80;

        for (int i = 0; i < 8; ++i) {
            buffer[paddedLen - 1 - i] = static_cast<uint8_t>((totalBits >> (i * 8)) & 0xFF);
        }

        for (size_t chunk = 0; chunk < paddedLen; chunk += 64) {
            uint32_t W[64];
            for (int t = 0; t < 16; ++t) {
                W[t] = (buffer[chunk + t * 4] << 24) |
                       (buffer[chunk + t * 4 + 1] << 16) |
                       (buffer[chunk + t * 4 + 2] << 8) |
                       (buffer[chunk + t * 4 + 3]);
            }
            for (int t = 16; t < 64; ++t) {
                W[t] = theta1(W[t - 2]) + W[t - 7] + theta0(W[t - 15]) + W[t - 16];
            }

            uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

            for (int t = 0; t < 64; ++t) {
                uint32_t T1 = h + sig1(e) + choose(e, f, g) + K256[t] + W[t];
                uint32_t T2 = sig0(a) + majority(a, b, c);
                h = g; g = f; f = e; e = d + T1;
                d = c; c = b; b = a; a = T1 + T2;
            }

            H[0] += a; H[1] += b; H[2] += c; H[3] += d;
            H[4] += e; H[5] += f; H[6] += g; H[7] += h;
        }

        std::ostringstream oss;
        for (int i = 0; i < 8; ++i) {
            oss << std::hex << std::setw(8) << std::setfill('0') << H[i];
        }
        return oss.str();
    }

    // ================= MD5 =================
    inline uint32_t rotl32(uint32_t x, uint32_t n) { return (x << n) | (x >> (32 - n)); }

    std::string computeMd5(const uint8_t* initial_msg, size_t initial_len)
    {
        uint32_t h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476;

        size_t new_len = ((((initial_len + 8) / 64) + 1) * 64);
        std::vector<uint8_t> msg(new_len, 0);
        std::memcpy(msg.data(), initial_msg, initial_len);
        msg[initial_len] = 0x80;

        uint64_t bits_len = 8 * initial_len;
        std::memcpy(msg.data() + new_len - 8, &bits_len, 8);

        static const uint32_t k[64] = {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        };

        static const uint32_t r[64] = {
            7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
        };

        for (size_t offset = 0; offset < new_len; offset += 64) {
            const uint32_t* w = reinterpret_cast<const uint32_t*>(msg.data() + offset);
            uint32_t a = h0, b = h1, c = h2, d = h3;

            for (uint32_t i = 0; i < 64; ++i) {
                uint32_t f, g;
                if (i < 16) {
                    f = (b & c) | ((~b) & d);
                    g = i;
                } else if (i < 32) {
                    f = (d & b) | ((~d) & c);
                    g = (5 * i + 1) % 16;
                } else if (i < 48) {
                    f = b ^ c ^ d;
                    g = (3 * i + 5) % 16;
                } else {
                    f = c ^ (b | (~d));
                    g = (7 * i) % 16;
                }

                uint32_t temp = d;
                d = c;
                c = b;
                b = b + rotl32(a + f + k[i] + w[g], r[i]);
                a = temp;
            }

            h0 += a; h1 += b; h2 += c; h3 += d;
        }

        std::ostringstream oss;
        for (uint32_t val : {h0, h1, h2, h3}) {
            for (int i = 0; i < 4; ++i) {
                oss << std::hex << std::setw(2) << std::setfill('0') << ((val >> (i * 8)) & 0xFF);
            }
        }
        return oss.str();
    }

    // ================= SHA-1 =================
    std::string computeSha1(const uint8_t* data, size_t length)
    {
        uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
        size_t paddedLen = ((length + 8) / 64 + 1) * 64;
        std::vector<uint8_t> buffer(paddedLen, 0);
        std::memcpy(buffer.data(), data, length);
        buffer[length] = 0x80;

        uint64_t totalBits = length * 8;
        for (int i = 0; i < 8; ++i) {
            buffer[paddedLen - 1 - i] = static_cast<uint8_t>((totalBits >> (i * 8)) & 0xFF);
        }

        for (size_t chunk = 0; chunk < paddedLen; chunk += 64) {
            uint32_t w[80];
            for (int t = 0; t < 16; ++t) {
                w[t] = (buffer[chunk + t * 4] << 24) |
                       (buffer[chunk + t * 4 + 1] << 16) |
                       (buffer[chunk + t * 4 + 2] << 8) |
                       (buffer[chunk + t * 4 + 3]);
            }
            for (int t = 16; t < 80; ++t) {
                w[t] = rotl32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
            }

            uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;

            for (int t = 0; t < 80; ++t) {
                uint32_t f, k;
                if (t < 20) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                } else if (t < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (t < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                uint32_t temp = rotl32(a, 5) + f + e + k + w[t];
                e = d; d = c; c = rotl32(b, 30); b = a; a = temp;
            }

            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
        }

        std::ostringstream oss;
        for (uint32_t val : {h0, h1, h2, h3, h4}) {
            oss << std::hex << std::setw(8) << std::setfill('0') << val;
        }
        return oss.str();
    }
}

BinaryFile::BinaryFile(const std::string& path)
    : filePath(path)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        throw std::runtime_error("Dosya acilamadi: " + path);
    }

    std::streamsize fileSize = file.tellg();
    if (fileSize < 0)
    {
        throw std::runtime_error("Dosya boyutu okunamadi: " + path);
    }

    file.seekg(0, std::ios::beg);
    data.resize(static_cast<size_t>(fileSize));

    if (fileSize > 0)
    {
        if (!file.read(reinterpret_cast<char*>(data.data()), fileSize))
        {
            throw std::runtime_error("Dosya okunurken hata olustu: " + path);
        }
    }
}

const std::string& BinaryFile::getFilePath() const
{
    return filePath;
}

size_t BinaryFile::getSize() const
{
    return data.size();
}

const std::vector<uint8_t>& BinaryFile::getData() const
{
    return data;
}

uint8_t BinaryFile::readByte(size_t offset) const
{
    if (offset >= data.size())
    {
        throw std::out_of_range("BinaryFile::readByte aralik disi (offset: " + std::to_string(offset) + ")");
    }
    return data[offset];
}

uint16_t BinaryFile::readUInt16(size_t offset) const
{
    if (offset + 1 >= data.size())
    {
        throw std::out_of_range("BinaryFile::readUInt16 aralik disi");
    }
    return static_cast<uint16_t>(data[offset])
        | (static_cast<uint16_t>(data[offset + 1]) << 8);
}

uint32_t BinaryFile::readUInt32(size_t offset) const
{
    if (offset + 3 >= data.size())
    {
        throw std::out_of_range("BinaryFile::readUInt32 aralik disi");
    }
    return static_cast<uint32_t>(data[offset])
        | (static_cast<uint32_t>(data[offset + 1]) << 8)
        | (static_cast<uint32_t>(data[offset + 2]) << 16)
        | (static_cast<uint32_t>(data[offset + 3]) << 24);
}

uint64_t BinaryFile::readUInt64(size_t offset) const
{
    if (offset + 7 >= data.size())
    {
        throw std::out_of_range("BinaryFile::readUInt64 aralik disi");
    }
    uint64_t low = readUInt32(offset);
    uint64_t high = readUInt32(offset + 4);
    return low | (high << 32);
}

std::string BinaryFile::readAsciiString(size_t offset, size_t maxLength) const
{
    std::string result;
    for (size_t i = 0; i < maxLength && (offset + i) < data.size(); ++i)
    {
        char c = static_cast<char>(data[offset + i]);
        if (c == '\0') break;
        result += c;
    }
    return result;
}

std::vector<uint8_t> BinaryFile::readBytes(size_t offset, size_t count) const
{
    if (offset > data.size())
    {
        return {};
    }
    size_t actualCount = std::min(count, data.size() - offset);
    return std::vector<uint8_t>(data.begin() + offset, data.begin() + offset + actualCount);
}

double BinaryFile::calculateEntropy(const uint8_t* buffer, size_t length)
{
    if (length == 0 || buffer == nullptr)
    {
        return 0.0;
    }

    std::array<size_t, 256> frequencies{};
    for (size_t i = 0; i < length; ++i)
    {
        frequencies[buffer[i]]++;
    }

    double entropy = 0.0;
    for (size_t i = 0; i < 256; ++i)
    {
        if (frequencies[i] > 0)
        {
            double p = static_cast<double>(frequencies[i]) / length;
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

double BinaryFile::getOverallEntropy() const
{
    return calculateEntropy(data.data(), data.size());
}

std::string BinaryFile::getMD5() const
{
    return computeMd5(data.data(), data.size());
}

std::string BinaryFile::computeMD5String(const std::string& input)
{
    return computeMd5(reinterpret_cast<const uint8_t*>(input.data()), input.size());
}

std::string BinaryFile::getSHA1() const
{
    return computeSha1(data.data(), data.size());
}

std::string BinaryFile::getSHA256() const
{
    return computeSha256(data.data(), data.size());
}

std::vector<ExtractedString> BinaryFile::extractStrings(size_t minLength, size_t maxCount) const
{
    std::vector<ExtractedString> strings;
    strings.reserve(maxCount);

    size_t n = data.size();

    // 1. ASCII Taraması
    std::string curAscii;
    size_t startOffset = 0;

    for (size_t i = 0; i < n && strings.size() < maxCount; ++i)
    {
        uint8_t b = data[i];
        if (b >= 32 && b <= 126)
        {
            if (curAscii.empty()) startOffset = i;
            curAscii.push_back(static_cast<char>(b));
        }
        else
        {
            if (curAscii.size() >= minLength)
            {
                strings.push_back({curAscii, startOffset, false});
            }
            curAscii.clear();
        }
    }
    if (curAscii.size() >= minLength && strings.size() < maxCount)
    {
        strings.push_back({curAscii, startOffset, false});
    }

    // 2. UTF-16LE Unicode Taraması
    std::string curUtf16;
    size_t startUtf16Offset = 0;

    for (size_t i = 0; i + 1 < n && strings.size() < maxCount; i += 2)
    {
        uint8_t c = data[i];
        uint8_t zero = data[i + 1];

        if (zero == 0x00 && c >= 32 && c <= 126)
        {
            if (curUtf16.empty()) startUtf16Offset = i;
            curUtf16.push_back(static_cast<char>(c));
        }
        else
        {
            if (curUtf16.size() >= minLength)
            {
                strings.push_back({curUtf16, startUtf16Offset, true});
            }
            curUtf16.clear();
        }
    }
    if (curUtf16.size() >= minLength && strings.size() < maxCount)
    {
        strings.push_back({curUtf16, startUtf16Offset, true});
    }

    return strings;
}
