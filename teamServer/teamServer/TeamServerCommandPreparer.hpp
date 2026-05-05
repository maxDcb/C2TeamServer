#pragma once

#include <string>
#include <vector>

class C2Message;

struct TeamServerCommandPreparerContext
{
    std::string input;
    std::vector<std::string> tokens;
    bool isWindows = true;
    std::string windowsArch = "x64";
};

struct TeamServerCommandPreparerResult
{
    bool handled = false;
    int status = 0;
};

class TeamServerCommandPreparer
{
public:
    virtual ~TeamServerCommandPreparer() = default;

    virtual bool canPrepare(const std::string& instruction) const = 0;
    virtual TeamServerCommandPreparerResult prepare(
        const TeamServerCommandPreparerContext& context,
        C2Message& c2Message) const = 0;
};
