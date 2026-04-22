#include <iostream>

#include "TeamServer.hpp"
#include "TeamServerBootstrap.hpp"

int main(int argc, char* argv[])
{
    std::string configFile = "TeamServerConfig.json";
    if (argc >= 2)
    {
        configFile = argv[1];
    }

    try
    {
        auto config = loadTeamServerConfigFile(configFile);
        auto logger = createTeamServerLogger(config);

        TeamServer service(config);
        TeamServerTlsMaterial tlsMaterial = loadTeamServerTlsMaterial(config, logger);
        auto server = buildAndStartTeamServerServer(config, service, tlsMaterial);

        logger->info("Team Server listening on {0}", buildTeamServerGrpcAddress(config));
        server->Wait();
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
}
