#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <iostream>
#include <stdexcept>
#include <string>

#include "TeamServer.hpp"
#include "TeamServerBootstrap.hpp"
#include "TeamServerInstance.hpp"
#include "TeamServerSecurity.hpp"

namespace fs = std::filesystem;

namespace
{
struct CommandLine
{
    std::string command;
    TeamServerInstanceOptions init;
    fs::path instanceRoot;
};

std::string readBootstrapPasswordFile(const fs::path& path)
{
    const fs::path absolutePath = fs::absolute(path);
    requirePrivateTeamServerFile(absolutePath, "Bootstrap password file", true);
    std::ifstream input(absolutePath, std::ios::binary);
    std::string password(std::istreambuf_iterator<char>(input), {});
    while (!password.empty() && (password.back() == '\n' || password.back() == '\r'))
        password.pop_back();
    if (password.size() < 16)
        throw std::runtime_error("Bootstrap password file must contain at least 16 characters");
    return password;
}

std::string requireValue(int& index, int argc, char* argv[], const std::string& option)
{
    if (++index >= argc)
        throw std::runtime_error("Missing value for " + option);
    return argv[index];
}

void printUsage()
{
    std::cout
        << "Exploration TeamServer 1.0.0-rc.1\n\n"
        << "Usage:\n"
        << "  TeamServer                         Initialize a local standalone instance if needed, then run\n"
        << "  TeamServer init [options]          Create an isolated instance\n"
        << "  TeamServer run [--instance-dir P]  Run an initialized instance\n"
        << "  TeamServer version\n\n"
        << "Init options:\n"
        << "  --profile development|standalone|production\n"
        << "  --instance-dir PATH  --hostname NAME  --listen-address ADDRESS  --port PORT\n"
        << "  --tls-cert PATH  --tls-key PATH  --trust-cert PATH\n"
        << "  --client-ca PATH  --require-client-cert  --admin-username NAME  --force\n"
        << "  --bootstrap-password-file PATH (recommended for production)\n"
        << "Set C2_BOOTSTRAP_PASSWORD_FILE for production or C2_BOOTSTRAP_PASSWORD for local development.\n";
}

CommandLine parseArguments(int argc, char* argv[], const fs::path& releaseRoot)
{
    CommandLine result;
    result.command = argc > 1 ? argv[1] : "default";
    result.instanceRoot = defaultTeamServerInstanceRoot();
    result.init.instanceRoot = result.instanceRoot;
    result.init.releaseRoot = releaseRoot;
    const char* passwordFile = std::getenv("C2_BOOTSTRAP_PASSWORD_FILE");
    const char* password = std::getenv("C2_BOOTSTRAP_PASSWORD");
    if (passwordFile && *passwordFile && password && *password)
        throw std::runtime_error("Set only one of C2_BOOTSTRAP_PASSWORD_FILE and C2_BOOTSTRAP_PASSWORD");
    if (passwordFile && *passwordFile)
        result.init.adminPassword = readBootstrapPasswordFile(passwordFile);
    else if (password && *password)
        result.init.adminPassword = password;

    for (int index = 2; index < argc; ++index)
    {
        const std::string option = argv[index];
        if (option == "--instance-dir")
        {
            result.instanceRoot = requireValue(index, argc, argv, option);
            result.init.instanceRoot = result.instanceRoot;
        }
        else if (option == "--profile")
            result.init.profile = parseTeamServerProfile(requireValue(index, argc, argv, option));
        else if (option == "--hostname")
            result.init.hostname = requireValue(index, argc, argv, option);
        else if (option == "--listen-address")
            result.init.listenAddress = requireValue(index, argc, argv, option);
        else if (option == "--port")
            result.init.port = std::stoi(requireValue(index, argc, argv, option));
        else if (option == "--tls-cert")
            result.init.tlsCertificate = requireValue(index, argc, argv, option);
        else if (option == "--tls-key")
            result.init.tlsPrivateKey = requireValue(index, argc, argv, option);
        else if (option == "--trust-cert")
            result.init.trustCertificate = requireValue(index, argc, argv, option);
        else if (option == "--client-ca")
            result.init.clientCaCertificate = requireValue(index, argc, argv, option);
        else if (option == "--require-client-cert")
            result.init.requireClientCertificate = true;
        else if (option == "--admin-username")
            result.init.adminUsername = requireValue(index, argc, argv, option);
        else if (option == "--bootstrap-password-file")
            result.init.adminPassword = readBootstrapPasswordFile(requireValue(index, argc, argv, option));
        else if (option == "--force")
            result.init.force = true;
        else if (option == "--help" || option == "-h")
            result.command = "help";
        else
            throw std::runtime_error("Unknown option: " + option);
    }
    return result;
}

int runInstance(const fs::path& instanceRoot)
{
    const fs::path configFile = fs::absolute(instanceRoot) / "config" / "TeamServerConfig.json";
    const auto config = loadTeamServerConfigFile(configFile.string());
    const auto logger = createTeamServerLogger(config);
    TeamServer service(config);
    const TeamServerTlsMaterial tlsMaterial = loadTeamServerTlsMaterial(config, logger);
    auto server = buildAndStartTeamServerServer(config, service, tlsMaterial);
    logger->info("TeamServer 1.0.0-rc.1 listening securely on {}", buildTeamServerGrpcAddress(config));
    server->Wait();
    return 0;
}
} // namespace

int main(int argc, char* argv[])
{
    try
    {
        const fs::path executable = fs::weakly_canonical(fs::absolute(argv[0]));
        const fs::path releaseRoot = executable.parent_path().parent_path();
        CommandLine command = parseArguments(argc, argv, releaseRoot);

        if (command.command == "help")
        {
            printUsage();
            return 0;
        }
        if (command.command == "version")
        {
            std::cout << "1.0.0-rc.1\n";
            return 0;
        }
        if (command.command == "init")
        {
            const TeamServerInstanceResult initialized = initializeTeamServerInstance(command.init);
            std::cout << "Instance initialized: " << command.init.instanceRoot << '\n'
                      << "Client profile: " << initialized.clientProfileFile << '\n'
                      << "Bootstrap credentials: " << initialized.bootstrapFile << '\n'
                      << "TLS SHA-256 fingerprint: " << initialized.certificateFingerprint << '\n';
            return 0;
        }
        if (command.command == "run")
            return runInstance(command.instanceRoot);
        if (command.command == "default")
        {
            const fs::path config = command.instanceRoot / "config" / "TeamServerConfig.json";
            if (!fs::exists(config))
            {
                const TeamServerInstanceResult initialized = initializeTeamServerInstance(command.init);
                std::cout << "Created a unique standalone instance.\n"
                          << "Client profile: " << initialized.clientProfileFile << '\n'
                          << "Bootstrap credentials: " << initialized.bootstrapFile << '\n';
            }
            return runInstance(command.instanceRoot);
        }
        throw std::runtime_error("Unknown command: " + command.command);
    }
    catch (const std::exception& error)
    {
        std::cerr << "TeamServer: " << error.what() << '\n';
        return 1;
    }
}
