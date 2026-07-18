#include "TeamServerCommandPreparationService.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <utility>

#include "TeamServerCredentialVaultService.hpp"
#include "TeamServerRuntimeConfig.hpp"

namespace fs = std::filesystem;

namespace
{
struct ResolvedCredential
{
    std::string domain;
    std::string username;
    std::string password;
};

std::string lowerString(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c)
    {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool isCredentialReference(const std::string& value)
{
    return value.rfind("cred:", 0) == 0;
}

bool isVaultFlag(const std::string& value)
{
    return lowerString(value) == "--vault";
}

std::string credentialIdFromVaultValue(std::string value)
{
    if (isCredentialReference(value))
        value = value.substr(5);

    const std::size_t labelStart = value.find('(');
    if (labelStart != std::string::npos)
        value = value.substr(0, labelStart);
    return value;
}

std::string credentialUsername(const ResolvedCredential& credential, bool includeDomain)
{
    if (!includeDomain || credential.domain.empty())
        return credential.username;
    return credential.domain + "\\" + credential.username;
}

bool isPasswordFlag(const std::string& value)
{
    const std::string lower = lowerString(value);
    return value == "-p" || lower == "--password";
}

bool isUsernameFlag(const std::string& value)
{
    const std::string lower = lowerString(value);
    return lower == "-u" || lower == "--user";
}

bool isPsExecAuthFlag(const std::string& value)
{
    const std::string lower = lowerString(value);
    return lower == "-u" || lower == "-k" || lower == "-n";
}

bool isVaultEnabledCommand(const std::string& instruction)
{
    const std::string lower = lowerString(instruction);
    return lower == "maketoken"
        || lower == "spawnas"
        || lower == "psexec"
        || lower == "wmiexec"
        || lower == "winrm"
        || lower == "dcomexec"
        || lower == "cimexec"
        || lower == "taskscheduler"
        || lower == "sshexec";
}

bool containsPsExecAuthFlag(const std::vector<std::string>& tokens)
{
    return std::any_of(tokens.begin() + 1, tokens.end(), isPsExecAuthFlag);
}

bool containsUsernameOrPasswordFlag(const std::vector<std::string>& tokens)
{
    return std::any_of(tokens.begin() + 1, tokens.end(), [](const std::string& token)
    {
        return isUsernameFlag(token) || isPasswordFlag(token);
    });
}

std::vector<std::string>::iterator commandTailSeparator(std::vector<std::string>& tokens)
{
    return std::find(tokens.begin() + 1, tokens.end(), "--");
}

bool usesLegacyCredentialReference(const std::vector<std::string>& tokens, const std::string& instruction)
{
    if (instruction == "maketoken")
        return tokens.size() > 1 && isCredentialReference(tokens[1]);

    if (instruction == "spawnas")
    {
        for (std::size_t i = 1; i < tokens.size(); ++i)
        {
            const std::string token = lowerString(tokens[i]);
            if (token == "--")
                return false;
            if (token == "-d" || token == "--domain" || token == "-l" || token == "--logon-type")
            {
                ++i;
                continue;
            }
            if (isCredentialReference(tokens[i]))
                return true;
        }
        return false;
    }

    if (instruction == "psexec" || instruction == "wmiexec" || instruction == "winrm")
    {
        for (std::size_t i = 1; i + 1 < tokens.size(); ++i)
        {
            if (lowerString(tokens[i]) == "-u" && isCredentialReference(tokens[i + 1]))
                return true;
        }
        return false;
    }

    if (instruction == "dcomexec" || instruction == "cimexec" || instruction == "taskscheduler" || instruction == "sshexec")
    {
        for (std::size_t i = 1; i + 1 < tokens.size(); ++i)
        {
            if (isUsernameFlag(tokens[i]) && isCredentialReference(tokens[i + 1]))
                return true;
        }
    }
    return false;
}
} // namespace

TeamServerCommandPreparationService::TeamServerCommandPreparationService(
    std::shared_ptr<spdlog::logger> logger,
    TeamServerRuntimeConfig runtimeConfig,
    CommonCommands& commonCommands,
    std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd,
    std::vector<std::unique_ptr<TeamServerCommandPreparer>> preparers,
    std::shared_ptr<TeamServerCredentialVaultService> credentialVaultService)
    : m_logger(std::move(logger)),
      m_runtimeConfig(std::move(runtimeConfig)),
      m_commonCommands(commonCommands),
      m_moduleCmd(moduleCmd),
      m_preparers(std::move(preparers)),
      m_credentialVaultService(std::move(credentialVaultService))
{
}

void TeamServerCommandPreparationService::splitInputCmd(const std::string& input, std::vector<std::string>& splitedList) const
{
    std::string tmp;
    for (size_t i = 0; i < input.size(); i++)
    {
        const char c = input[i];
        if (c == ' ')
        {
            if (!tmp.empty())
                splitedList.push_back(tmp);
            tmp.clear();
        }
        else if (c == '\'')
        {
            i++;
            while (input[i] != '\'')
            {
                tmp += input[i];
                i++;
            }
        }
        else
        {
            tmp += c;
        }
    }

    if (!tmp.empty())
        splitedList.push_back(tmp);
}

std::string TeamServerCommandPreparationService::toLower(const std::string& str)
{
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c)
        { return static_cast<char>(std::tolower(c)); });
    return result;
}

bool TeamServerCommandPreparationService::rewriteCredentialReferences(std::vector<std::string>& tokens, C2Message& c2Message) const
{
    if (tokens.empty())
        return true;
    if (!m_credentialVaultService)
    {
        if (std::any_of(tokens.begin() + 1, tokens.end(), isVaultFlag))
        {
            c2Message.set_returnvalue("Credential vault service is not available.");
            return false;
        }
        return true;
    }

    auto resolve = [&](const std::string& reference, ResolvedCredential& credential) -> bool
    {
        const std::string credentialId = credentialIdFromVaultValue(reference);
        if (credentialId.empty())
            return false;

        teamserverapi::CredentialSelector selector;
        selector.set_credential_id(credentialId);
        selector.set_reveal_secret(true);
        teamserverapi::CredentialDetail detail;
        m_credentialVaultService->getCredential(selector, &detail);
        if (detail.status() != teamserverapi::OK)
        {
            c2Message.set_returnvalue("Credential not found: " + reference + ".");
            return false;
        }

        credential.domain = detail.summary().domain();
        credential.username = detail.summary().username();
        for (const auto& secret : detail.secrets())
        {
            const std::string name = lowerString(secret.name());
            if (name == "password" || name == "manual" || name == "secret")
            {
                credential.password = secret.value();
                break;
            }
        }

        if (credential.username.empty() || credential.password.empty())
        {
            c2Message.set_returnvalue("Credential " + reference + " must contain username and password secret.");
            return false;
        }
        return true;
    };

    const std::string instruction = lowerString(tokens[0]);
    if (!isVaultEnabledCommand(instruction))
    {
        if (std::any_of(tokens.begin() + 1, tokens.end(), isVaultFlag))
        {
            c2Message.set_returnvalue("--vault is not supported by command: " + tokens[0] + ".");
            return false;
        }
        return true;
    }

    bool hasVault = false;
    ResolvedCredential vaultCredential;
    for (std::size_t i = 1; i < tokens.size(); ++i)
    {
        if (!isVaultFlag(tokens[i]))
            continue;

        if (hasVault)
        {
            c2Message.set_returnvalue("Only one --vault credential can be used.");
            return false;
        }
        if (i + 1 >= tokens.size())
        {
            c2Message.set_returnvalue("Usage: " + tokens[0] + " --vault <credential_id> ...");
            return false;
        }

        if (!resolve(tokens[i + 1], vaultCredential))
            return false;
        tokens.erase(tokens.begin() + static_cast<std::ptrdiff_t>(i), tokens.begin() + static_cast<std::ptrdiff_t>(i + 2));
        hasVault = true;
        --i;
    }

    if (!hasVault)
    {
        if (usesLegacyCredentialReference(tokens, instruction))
        {
            c2Message.set_returnvalue("Use --vault <credential_id> instead of placing credential references in command arguments.");
            return false;
        }
        return true;
    }

    if (instruction == "psexec" || instruction == "wmiexec" || instruction == "winrm")
    {
        if (containsPsExecAuthFlag(tokens))
        {
            c2Message.set_returnvalue("Do not combine --vault with explicit authentication mode flags.");
            return false;
        }
        tokens.insert(tokens.begin() + 1, {"-u", credentialUsername(vaultCredential, true), vaultCredential.password});
        return true;
    }

    if (instruction == "maketoken")
    {
        if (tokens.size() > 1)
        {
            c2Message.set_returnvalue("Do not combine --vault with explicit username/password arguments.");
            return false;
        }
        tokens.insert(tokens.end(), {credentialUsername(vaultCredential, true), vaultCredential.password});
        return true;
    }

    if (instruction == "spawnas")
    {
        for (std::size_t i = 1; i < tokens.size(); ++i)
        {
            const std::string token = lowerString(tokens[i]);
            if (token == "--")
                break;
            if (token == "-d" || token == "--domain" || token == "-l" || token == "--logon-type")
            {
                ++i;
                continue;
            }
            if (token == "-p" || token == "--with-profile" || token == "--no-profile" || token == "-w" || token == "--show-window" || token == "--netonly")
                continue;
            if (!token.empty())
            {
                c2Message.set_returnvalue("Do not combine --vault with explicit username/password arguments.");
                return false;
            }
        }
        tokens.insert(commandTailSeparator(tokens), {credentialUsername(vaultCredential, true), vaultCredential.password});
        return true;
    }

    if (instruction == "sshexec")
    {
        if (containsUsernameOrPasswordFlag(tokens))
        {
            c2Message.set_returnvalue("Do not combine --vault with explicit username or password options.");
            return false;
        }
        tokens.insert(commandTailSeparator(tokens), {"-u", credentialUsername(vaultCredential, false), "--password", vaultCredential.password});
        return true;
    }

    if (instruction == "dcomexec" || instruction == "cimexec" || instruction == "taskscheduler")
    {
        if (containsUsernameOrPasswordFlag(tokens) || (instruction == "dcomexec" && std::find(tokens.begin() + 1, tokens.end(), "-n") != tokens.end()))
        {
            c2Message.set_returnvalue("Do not combine --vault with explicit username or password options.");
            return false;
        }
        tokens.insert(tokens.end(), {"-u", credentialUsername(vaultCredential, true), "-p", vaultCredential.password});
        return true;
    }

    return true;
}

int TeamServerCommandPreparationService::prepareMessage(
    const std::string& input,
    C2Message& c2Message,
    bool isWindows,
    const std::string& windowsArch) const
{
    m_logger->trace("prepMsg");

    std::vector<std::string> splitedCmd;
    splitInputCmd(input, splitedCmd);
    if (splitedCmd.empty())
        return 0;
    if (!rewriteCredentialReferences(splitedCmd, c2Message))
        return -1;

    int res = 0;
    const std::string instruction = splitedCmd[0];
    std::string normalizedTargetArch = isWindows
        ? TeamServerRuntimeConfig::normalizeWindowsArch(windowsArch)
        : TeamServerRuntimeConfig::normalizeLinuxArch(windowsArch);
    if (normalizedTargetArch.empty())
        normalizedTargetArch = isWindows ? m_runtimeConfig.defaultWindowsArch : m_runtimeConfig.defaultLinuxArch;
    bool isModuleFound = false;

    TeamServerCommandPreparerContext preparerContext;
    preparerContext.input = input;
    preparerContext.tokens = splitedCmd;
    preparerContext.isWindows = isWindows;
    preparerContext.windowsArch = normalizedTargetArch;
    for (const auto& preparer : m_preparers)
    {
        if (!preparer || !preparer->canPrepare(instruction))
            continue;
        TeamServerCommandPreparerResult prepared = preparer->prepare(preparerContext, c2Message);
        if (prepared.handled)
        {
            m_logger->trace("prepMsg end");
            return prepared.status;
        }
    }

    for (int i = 0; i < m_commonCommands.getNumberOfCommand(); i++)
    {
        if (instruction != m_commonCommands.getCommand(i))
            continue;

        if (instruction == LoadModuleInstruction && splitedCmd.size() == 2)
        {
            std::string param = splitedCmd[1];
            if (param == "ls")
                param = "listDirectory";
            else if (param == "cd")
                param = "changeDirectory";
            else if (param == "ps")
                param = "listProcesses";
            else if (param == "pwd")
                param = "printWorkingDirectory";

            if (!((param.size() >= 3 && param.substr(param.size() - 3) == ".so")
                    || (param.size() >= 4 && param.substr(param.size() - 3) == ".dll")))
            {
                m_logger->debug("Translate instruction to module name to load in {0}", m_runtimeConfig.teamServerModulesDirectoryPath.c_str());
                try
                {
                    for (const auto& entry : fs::recursive_directory_iterator(m_runtimeConfig.teamServerModulesDirectoryPath))
                    {
                        if (!fs::is_regular_file(entry.path()) || entry.path().extension() != ".so")
                            continue;

                        std::string moduleName = entry.path().filename();
                        moduleName = moduleName.substr(3);
                        moduleName = moduleName.substr(0, moduleName.length() - 3);

                        if (toLower(param) == toLower(moduleName))
                        {
                            splitedCmd[1] = isWindows ? moduleName + ".dll" : entry.path().filename().string();
                            m_logger->debug("Found module to load {0}", splitedCmd[1]);
                        }
                    }
                }
                catch (const fs::filesystem_error&)
                {
                    m_logger->warn("Error accessing module directory");
                }
            }
        }

        m_logger->debug("Preparing common command={0} isWindows={1} targetArch={2}", instruction, isWindows, normalizedTargetArch);
        res = m_commonCommands.init(splitedCmd, c2Message, isWindows, normalizedTargetArch);
        if (instruction == LoadModuleInstruction && res == 0)
        {
            m_logger->info(
                "loadModule resolved module input={0} isWindows={1} targetArch={2} path={3}",
                splitedCmd.size() > 1 ? splitedCmd[1] : "",
                isWindows,
                normalizedTargetArch,
                m_commonCommands.getLastResolvedModulePath());
        }
        isModuleFound = true;
    }

    for (auto it = m_moduleCmd.begin(); it != m_moduleCmd.end(); ++it)
    {
        if (toLower(instruction) != toLower((*it)->getName()))
            continue;

        splitedCmd[0] = (*it)->getName();
        (*it)->setWindowsArch(normalizedTargetArch);
        m_logger->debug("Preparing module command={0} isWindows={1} targetArch={2}", splitedCmd[0], isWindows, normalizedTargetArch);
        res = (*it)->init(splitedCmd, c2Message);
        isModuleFound = true;
    }

    if (!isModuleFound)
    {
        m_logger->warn("Module {0} not found.", instruction);
        c2Message.set_returnvalue("Module " + instruction + " not found.");
        res = -1;
    }

    m_logger->trace("prepMsg end");
    return res;
}
