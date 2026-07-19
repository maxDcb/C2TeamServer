#include "TeamServerBootstrap.hpp"

#include "TeamServer.hpp"
#include "TeamServerSecurity.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <unordered_map>

#include <grpcpp/server_builder.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "spdlog/logger.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace
{
spdlog::level::level_enum parseLogLevel(std::string level, bool& unknown)
{
    std::transform(level.begin(), level.end(), level.begin(), [](unsigned char character)
        { return static_cast<char>(std::tolower(character)); });
    static const std::unordered_map<std::string, spdlog::level::level_enum> levels = {
        {"trace", spdlog::level::trace}, {"debug", spdlog::level::debug},
        {"info", spdlog::level::info}, {"warning", spdlog::level::warn},
        {"warn", spdlog::level::warn}, {"error", spdlog::level::err},
        {"critical", spdlog::level::critical}, {"off", spdlog::level::off}};
    const auto found = levels.find(level);
    unknown = found == levels.end();
    return unknown ? spdlog::level::info : found->second;
}

std::string readRequiredFile(const fs::path& path, const std::string& description)
{
    std::ifstream input(path, std::ios::binary);
    if (!input.good())
        throw std::runtime_error(description + " not found: " + path.string());
    return std::string(std::istreambuf_iterator<char>(input), {});
}

const json& requiredObject(const json& parent, const char* name)
{
    const auto value = parent.find(name);
    if (value == parent.end() || !value->is_object())
        throw std::runtime_error(std::string("Required configuration object is missing: ") + name);
    return *value;
}

std::string requiredString(const json& parent, const char* name)
{
    const auto value = parent.find(name);
    if (value == parent.end() || !value->is_string() || value->get<std::string>().empty())
        throw std::runtime_error(std::string("Required configuration string is missing: ") + name);
    return value->get<std::string>();
}

void validateConfigShape(const json& config)
{
    if (config.value("Version", std::string()) != "1.0.0-rc.1")
        throw std::runtime_error("Configuration version must be 1.0.0-rc.1");
    const std::string profile = config.value("Profile", std::string());
    if (profile != "development" && profile != "standalone" && profile != "production")
        throw std::runtime_error("Profile must be development, standalone, or production");

    const json& server = requiredObject(config, "Server");
    const std::string address = requiredString(server, "listen_address");
    (void)requiredString(server, "hostname");
    const int port = server.value("port", 0);
    const int maxMessageMb = server.value("max_message_mb", 0);
    if (port < 1 || port > 65535)
        throw std::runtime_error("Server.port is outside the valid range");
    if (maxMessageMb < 1 || maxMessageMb > 256)
        throw std::runtime_error("Server.max_message_mb must be between 1 and 256");
    if (profile == "development" && address != "127.0.0.1" && address != "::1")
        throw std::runtime_error("Development profile may only listen on loopback");

    const json& security = requiredObject(config, "Security");
    const json& authentication = requiredObject(security, "authentication");
    (void)requiredString(authentication, "credentials_file");
    const json& tls = requiredObject(security, "tls");
    (void)requiredString(tls, "certificate_file");
    (void)requiredString(tls, "private_key_file");
    if (tls.value("require_client_certificate", false)
        && tls.value("client_ca_file", std::string()).empty())
    {
        throw std::runtime_error("mTLS requires Security.tls.client_ca_file");
    }
}

void validateCertificateAndKey(
    const std::string& certificatePem,
    const std::string& privateKeyPem,
    const std::string& hostname)
{
    BIO* certificateBio = BIO_new_mem_buf(certificatePem.data(), static_cast<int>(certificatePem.size()));
    BIO* keyBio = BIO_new_mem_buf(privateKeyPem.data(), static_cast<int>(privateKeyPem.size()));
    X509* certificate = certificateBio ? PEM_read_bio_X509(certificateBio, nullptr, nullptr, nullptr) : nullptr;
    EVP_PKEY* privateKey = keyBio ? PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr) : nullptr;
    BIO_free(certificateBio);
    BIO_free(keyBio);
    if (!certificate || !privateKey)
    {
        X509_free(certificate);
        EVP_PKEY_free(privateKey);
        throw std::runtime_error("TLS certificate or private key is not valid PEM");
    }

    const bool keyMatches = X509_check_private_key(certificate, privateKey) == 1;
    const bool currentlyValid = X509_cmp_current_time(X509_get0_notBefore(certificate)) <= 0
        && X509_cmp_current_time(X509_get0_notAfter(certificate)) >= 0;
    const bool hostnameMatches = X509_check_host(
        certificate,
        hostname.c_str(),
        hostname.size(),
        X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,
        nullptr) == 1
        || X509_check_ip_asc(certificate, hostname.c_str(), 0) == 1;
    X509_free(certificate);
    EVP_PKEY_free(privateKey);

    if (!keyMatches)
        throw std::runtime_error("TLS certificate does not match its private key");
    if (!currentlyValid)
        throw std::runtime_error("TLS certificate is not currently valid");
    if (!hostnameMatches)
        throw std::runtime_error("TLS certificate does not contain the configured hostname or IP in its SAN");
}
} // namespace

nlohmann::json loadTeamServerConfigFile(const std::string& configFile)
{
    std::ifstream input(configFile);
    if (!input.good())
        throw std::runtime_error("Configuration file not found: " + configFile);
    json config;
    try
    {
        config = json::parse(input);
    }
    catch (const std::exception& error)
    {
        throw std::runtime_error("Configuration JSON is invalid: " + std::string(error.what()));
    }
    validateConfigShape(config);
    return config;
}

std::shared_ptr<spdlog::logger> createTeamServerLogger(const nlohmann::json& config)
{
    const fs::path logDirectory = requiredObject(config, "Runtime").value("log_directory", "logs");
    std::error_code error;
    fs::create_directories(logDirectory, error);
    if (error)
        throw std::runtime_error("Could not create log directory: " + error.message());

    bool unknownLevel = false;
    const auto level = parseLogLevel(config.value("LogLevel", "info"), unknownLevel);
    auto consoleSink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto fileSink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        (logDirectory / "TeamServer.txt").string(), 10 * 1024 * 1024, 3);
    consoleSink->set_level(level);
    fileSink->set_level(level);
    std::vector<spdlog::sink_ptr> sinks {consoleSink, fileSink};
    auto logger = std::make_shared<spdlog::logger>("TeamServer", sinks.begin(), sinks.end());
    logger->set_level(level);
    logger->flush_on(spdlog::level::warn);
    if (unknownLevel)
        logger->warn("Unknown log level requested; using info");
    return logger;
}

TeamServerTlsMaterial loadTeamServerTlsMaterial(
    const nlohmann::json& config,
    const std::shared_ptr<spdlog::logger>& logger)
{
    (void)logger;
    const json& tls = requiredObject(requiredObject(config, "Security"), "tls");
    const fs::path certificatePath = requiredString(tls, "certificate_file");
    const fs::path privateKeyPath = requiredString(tls, "private_key_file");
    const bool strictPermissions = config.value("Profile", "production") == "production";
    requirePrivateTeamServerFile(privateKeyPath, "TLS private key", strictPermissions);

    TeamServerTlsMaterial material;
    material.certificate = readRequiredFile(certificatePath, "TLS certificate");
    material.key = readRequiredFile(privateKeyPath, "TLS private key");
    const std::string clientCa = tls.value("client_ca_file", std::string());
    if (!clientCa.empty())
        material.rootCertificate = readRequiredFile(clientCa, "mTLS client CA certificate");
    validateCertificateAndKey(
        material.certificate,
        material.key,
        requiredString(requiredObject(config, "Server"), "hostname"));
    return material;
}

std::string buildTeamServerGrpcAddress(const nlohmann::json& config)
{
    const json& server = requiredObject(config, "Server");
    return requiredString(server, "listen_address") + ":" + std::to_string(server.at("port").get<int>());
}

std::unique_ptr<grpc::Server> buildAndStartTeamServerServer(
    const nlohmann::json& config,
    TeamServer& service,
    const TeamServerTlsMaterial& tlsMaterial)
{
    grpc::SslServerCredentialsOptions options;
    options.pem_key_cert_pairs.push_back({tlsMaterial.key, tlsMaterial.certificate});
    const json& tls = requiredObject(requiredObject(config, "Security"), "tls");
    if (tls.value("require_client_certificate", false))
    {
        options.pem_root_certs = tlsMaterial.rootCertificate;
        options.client_certificate_request = GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
    }
    else
    {
        options.client_certificate_request = GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE;
    }

    const int maxMessageBytes = requiredObject(config, "Server").at("max_message_mb").get<int>() * 1024 * 1024;
    grpc::ServerBuilder builder;
    int selectedPort = 0;
    builder.AddListeningPort(buildTeamServerGrpcAddress(config), grpc::SslServerCredentials(options), &selectedPort);
    builder.RegisterService(&service);
    builder.SetMaxSendMessageSize(maxMessageBytes);
    builder.SetMaxReceiveMessageSize(maxMessageBytes);
    auto server = builder.BuildAndStart();
    if (!server || selectedPort == 0)
        throw std::runtime_error("Could not bind the secure gRPC server");
    return server;
}
