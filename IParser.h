#pragma once

#include <string>

class IParser
{
public:
    virtual ~IParser() = default;

    virtual void parse() = 0;
    virtual void printReport() const = 0;
    virtual std::string getFormatName() const = 0;
};
