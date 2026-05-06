#include "TeamServerFileTransferCommandPreparer.hpp"

#include <algorithm>
#include <cctype>
#include <utility>

#include "modules/ModuleCmd/Common.hpp"

namespace
{
std::string toLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c)
    {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

TeamServerCommandPreparerResult handledError(C2Message& c2Message, const std::string& message)
{
    TeamServerCommandPreparerResult result;
    result.handled = true;
    result.status = -1;
    c2Message.set_returnvalue(message);
    return result;
}

std::vector<std::string> regroup(const std::vector<std::string>& tokens)
{
    return regroupStrings(tokens);
}
} // namespace

TeamServerFileTransferCommandPreparer::TeamServerFileTransferCommandPreparer(
    std::shared_ptr<spdlog::logger> logger,
    std::shared_ptr<TeamServerFileArtifactService> fileArtifactService,
    std::vector<std::unique_ptr<ModuleCmd>>& moduleCmd)
    : m_logger(std::move(logger)),
      m_fileArtifactService(std::move(fileArtifactService)),
      m_moduleCmd(moduleCmd)
{
}

bool TeamServerFileTransferCommandPreparer::canPrepare(const std::string& instruction) const
{
    const std::string lowered = toLower(instruction);
    return lowered == "download" || lowered == "upload";
}

TeamServerCommandPreparerResult TeamServerFileTransferCommandPreparer::prepare(
    const TeamServerCommandPreparerContext& context,
    C2Message& c2Message) const
{
    if (toLower(context.tokens.empty() ? "" : context.tokens[0]) == "download")
        return prepareDownload(context, c2Message);
    return prepareUpload(context, c2Message);
}

bool TeamServerFileTransferCommandPreparer::hasModule(const std::string& name) const
{
    const std::string lowered = toLower(name);
    for (const auto& module : m_moduleCmd)
    {
        if (module && toLower(module->getName()) == lowered)
            return true;
    }
    return false;
}

TeamServerCommandPreparerResult TeamServerFileTransferCommandPreparer::prepareDownload(
    const TeamServerCommandPreparerContext& context,
    C2Message& c2Message) const
{
    TeamServerCommandPreparerResult result;
    result.handled = true;
    result.status = -1;

    if (!hasModule("download"))
        return handledError(c2Message, "Module download not found.\n");
    if (!m_fileArtifactService)
        return handledError(c2Message, "File artifact service is not available.\n");

    const std::vector<std::string> tokens = regroup(context.tokens);
    if (tokens.size() < 2 || tokens.size() > 3)
        return handledError(c2Message, "Usage: download <remote_path> [artifact_name]\n");

    const std::string& remotePath = tokens[1];
    const std::string nameHint = tokens.size() == 3 ? tokens[2] : "";
    TeamServerPreparedDownloadArtifact artifact = m_fileArtifactService->prepareDownloadArtifact(
        remotePath,
        nameHint,
        context.isWindows,
        context.windowsArch);
    if (!artifact.ok)
        return handledError(c2Message, artifact.message + "\n");

    c2Message.set_instruction("download");
    c2Message.set_inputfile(remotePath);
    c2Message.set_outputfile(artifact.path);
    result.status = 0;
    if (m_logger)
        m_logger->info("Prepared download artifact path {}", artifact.path);
    return result;
}

TeamServerCommandPreparerResult TeamServerFileTransferCommandPreparer::prepareUpload(
    const TeamServerCommandPreparerContext& context,
    C2Message& c2Message) const
{
    TeamServerCommandPreparerResult result;
    result.handled = true;
    result.status = -1;

    if (!hasModule("upload"))
        return handledError(c2Message, "Module upload not found.\n");
    if (!m_fileArtifactService)
        return handledError(c2Message, "File artifact service is not available.\n");

    const std::vector<std::string> tokens = regroup(context.tokens);
    if (tokens.size() != 3)
        return handledError(c2Message, "Usage: upload <upload_artifact> <remote_path>\n");

    TeamServerPreparedInputArtifact artifact = m_fileArtifactService->resolveUploadArtifact(
        tokens[1],
        context.isWindows,
        context.windowsArch);
    if (!artifact.ok)
        return handledError(c2Message, artifact.message + "\n");

    c2Message.set_instruction("upload");
    c2Message.set_inputfile(artifact.artifact.name);
    c2Message.set_outputfile(tokens[2]);
    c2Message.set_data(artifact.bytes);
    result.status = 0;
    if (m_logger)
        m_logger->info("Prepared upload artifact {} -> {}", artifact.artifact.name, tokens[2]);
    return result;
}
