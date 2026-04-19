#include "TeamServerBootstrap.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <unordered_map>

#include <grpcpp/server_builder.h>

#include "TeamServer.hpp"
#include "spdlog/logger.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"

using json = nlohmann::json;

namespace
{
spdlog::level::level_enum parseLogLevel(std::string level, bool& isUnknown)
{
    isUnknown = false;

    std::transform(level.begin(), level.end(), level.begin(),
        [](unsigned char c)
        { return static_cast<char>(std::tolower(c)); });

    static const std::unordered_map<std::string, spdlog::level::level_enum> levelMap =
        {
            {"trace", spdlog::level::trace},
            {"debug", spdlog::level::debug},
            {"info", spdlog::level::info},
            {"warn", spdlog::level::warn},
            {"warning", spdlog::level::warn},
            {"err", spdlog::level::err},
            {"error", spdlog::level::err},
            {"critical", spdlog::level::critical},
            {"off", spdlog::level::off}};

    auto it = levelMap.find(level);
    if (it != levelMap.end())
        return it->second;

    isUnknown = true;
    return spdlog::level::info;
}

std::string readRequiredFile(const std::string& filePath, const char* description, const std::shared_ptr<spdlog::logger>& logger)
{
    std::ifstream input(filePath, std::ios::binary);
    if (!input.good())
    {
        logger->critical("{} not found.", description);
        throw std::runtime_error(std::string(description) + " not found.");
    }

    return std::string(std::istreambuf_iterator<char>(input), {});
}
} // namespace

nlohmann::json loadTeamServerConfigFile(const std::string& configFile)
{
    std::ifstream input(configFile);
    if (!input.is_open())
    {
        throw std::runtime_error("Error: Config file '" + configFile + "' not found or could not be opened.");
    }

    try
    {
        return json::parse(input);
    }
    catch (const json::parse_error& e)
    {
        throw std::runtime_error("Error: Failed to parse JSON in config file '" + configFile + "' - " + e.what());
    }
}

std::shared_ptr<spdlog::logger> createTeamServerLogger(const nlohmann::json& config)
{
    std::vector<spdlog::sink_ptr> sinks;

    auto consoleSink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto fileSink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("logs/TeamServer.txt", 1024 * 1024 * 10, 3);
    sinks.push_back(consoleSink);
    sinks.push_back(fileSink);

    std::string logLevel = "info";
    auto logLevelIt = config.find("LogLevel");
    if (logLevelIt != config.end() && logLevelIt->is_string())
        logLevel = logLevelIt->get<std::string>();

    bool isUnknownLogLevel = false;
    spdlog::level::level_enum configuredLevel = parseLogLevel(logLevel, isUnknownLogLevel);

    consoleSink->set_level(configuredLevel);
    fileSink->set_level(configuredLevel);

    auto logger = std::make_shared<spdlog::logger>("TeamServer", begin(sinks), end(sinks));
    logger->set_level(configuredLevel);
    logger->flush_on(spdlog::level::warn);

    if (isUnknownLogLevel)
        logger->warn("Unknown log level '{}' requested, defaulting to 'info'.", logLevel);

    logger->info("TeamServer logging initialized at {} level", spdlog::level::to_string_view(logger->level()));
    return logger;
}

TeamServerTlsMaterial loadTeamServerTlsMaterial(const nlohmann::json& config, const std::shared_ptr<spdlog::logger>& logger)
{
    TeamServerTlsMaterial material;
    material.certificate = readRequiredFile(config["ServCrtFile"].get<std::string>(), "Server ceritifcat file", logger);
    material.key = readRequiredFile(config["ServKeyFile"].get<std::string>(), "Server key file", logger);
    material.rootCertificate = readRequiredFile(config["RootCA"].get<std::string>(), "Root CA file", logger);
    return material;
}

std::string buildTeamServerGrpcAddress(const nlohmann::json& config)
{
    std::string serverAddress = config["ServerGRPCAdd"].get<std::string>();
    serverAddress += ':';
    serverAddress += config["ServerGRPCPort"].get<std::string>();
    return serverAddress;
}

std::unique_ptr<grpc::Server> buildAndStartTeamServerServer(
    const nlohmann::json& config,
    TeamServer& service,
    const TeamServerTlsMaterial& tlsMaterial)
{
    grpc::SslServerCredentialsOptions::PemKeyCertPair keycert =
        {
            tlsMaterial.key,
            tlsMaterial.certificate};

    grpc::SslServerCredentialsOptions sslOptions;
    sslOptions.pem_root_certs = tlsMaterial.rootCertificate;
    sslOptions.pem_key_cert_pairs.push_back(keycert);

    grpc::ServerBuilder builder;
    builder.AddListeningPort(buildTeamServerGrpcAddress(config), grpc::SslServerCredentials(sslOptions));
    builder.RegisterService(&service);
    builder.SetMaxSendMessageSize(1024 * 1024 * 1024);
    builder.SetMaxMessageSize(1024 * 1024 * 1024);
    builder.SetMaxReceiveMessageSize(1024 * 1024 * 1024);
    return builder.BuildAndStart();
}
