#pragma once

#include <memory>
#include <string>

#include "spdlog/logger.h"

struct TeamServerShellcodeRequest
{
    std::string generator = "raw";
    std::string sourcePath;
    std::string sourceType = "raw";
    std::string arch = "x64";
    std::string method;
    std::string arguments;
    std::string exitPolicy = "process";
};

struct TeamServerShellcodeResult
{
    bool ok = false;
    std::string message;
    std::string bytes;
    std::string sha256;
    std::string generator;
    std::string sourceType;
};

class TeamServerShellcodeService
{
public:
    explicit TeamServerShellcodeService(std::shared_ptr<spdlog::logger> logger);
    virtual ~TeamServerShellcodeService() = default;

    virtual TeamServerShellcodeResult generate(const TeamServerShellcodeRequest& request) const;

private:
    TeamServerShellcodeResult generateRaw(const TeamServerShellcodeRequest& request) const;
    TeamServerShellcodeResult generateDonut(const TeamServerShellcodeRequest& request) const;

    std::shared_ptr<spdlog::logger> m_logger;
};
