#include "TeamServerModuleLoader.hpp"

#include <dlfcn.h>

#include <filesystem>

namespace fs = std::filesystem;

namespace
{
using constructProc = ModuleCmd* (*)();
}

TeamServerModuleLoader::TeamServerModuleLoader(
    std::shared_ptr<spdlog::logger> logger,
    TeamServerRuntimeConfig runtimeConfig)
    : m_logger(std::move(logger)),
      m_runtimeConfig(std::move(runtimeConfig))
{
}

std::vector<std::unique_ptr<ModuleCmd>> TeamServerModuleLoader::loadModules() const
{
    std::vector<std::unique_ptr<ModuleCmd>> modules;

    m_logger->debug("TeamServer module directory path {0}", m_runtimeConfig.teamServerModulesDirectoryPath.c_str());

    try
    {
        for (const auto& entry : fs::recursive_directory_iterator(m_runtimeConfig.teamServerModulesDirectoryPath))
        {
            if (!fs::is_regular_file(entry.path()) || entry.path().extension() != ".so")
                continue;

            m_logger->debug("Trying to load {0}", entry.path().c_str());

            void* handle = dlopen(entry.path().c_str(), RTLD_LAZY);
            if (!handle)
            {
                m_logger->warn("Failed to load {0}: {1}", entry.path().c_str(), dlerror());
                continue;
            }

            std::string funcName = entry.path().filename();
            funcName = funcName.substr(3);
            funcName = funcName.substr(0, funcName.length() - 3);
            funcName += "Constructor";

            m_logger->debug("Looking for constructor function {0}", funcName);

            constructProc construct = reinterpret_cast<constructProc>(dlsym(handle, funcName.c_str()));
            if (!construct)
            {
                m_logger->warn("Failed to find constructor: {0}", dlerror());
                dlclose(handle);
                continue;
            }

            ModuleCmd* moduleCmd = construct();
            if (!moduleCmd)
            {
                m_logger->warn("Constructor returned null");
                dlclose(handle);
                continue;
            }

            std::unique_ptr<ModuleCmd> moduleCmdPtr(moduleCmd);
            m_runtimeConfig.configureModule(*moduleCmdPtr);
            m_logger->debug("Module {0} loaded", entry.path().filename().c_str());
            modules.push_back(std::move(moduleCmdPtr));
        }
    }
    catch (const fs::filesystem_error&)
    {
        m_logger->warn("Error accessing module directory");
    }

    if (modules.empty())
        m_logger->warn("No TeamServer modules loaded from {0}", m_runtimeConfig.teamServerModulesDirectoryPath.c_str());
    else
        m_logger->info("Loaded {0} TeamServer module(s) from {1}", modules.size(), m_runtimeConfig.teamServerModulesDirectoryPath.c_str());

    return modules;
}
