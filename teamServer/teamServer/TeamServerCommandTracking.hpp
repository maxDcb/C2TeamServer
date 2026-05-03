#pragma once

#include <string>

struct BeaconCommandContext
{
    std::string commandId;
    std::string beaconHash;
    std::string listenerHash;
    std::string commandLine;
    std::string instruction;
};
