#include "JobApplicationService.hpp"

#include <chrono>
#include <algorithm>
#include <iomanip>
#include <openssl/sha.h>
#include <sstream>
#include <utility>

#include "nlohmann/json.hpp"

namespace
{
std::int64_t nowMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string digest(const std::string& operation, const std::string& input)
{
    const std::string bytes = std::to_string(operation.size()) + ":" + operation
        + std::to_string(input.size()) + ":" + input;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), hash);
    std::ostringstream result;
    for (unsigned char value : hash)
        result << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(value);
    return result.str();
}

std::string normalize(const std::string& operation, const std::string& input)
{
    if (operation == "echo")
        return input;
    nlohmann::json value = nlohmann::json::parse(input, nullptr, false);
    if (operation == "reload_modules")
    {
        if (!value.is_object() || !value.empty())
            throw JobError(JobErrorCode::invalid_argument, "reload_modules takes no input.");
        return "{}";
    }
    if (operation == "host_artifact")
    {
        if (!value.is_object() || value.size() < 2 || value.size() > 3
            || !value.contains("listener_hash") || !value["listener_hash"].is_string()
            || !value.contains("artifact_reference") || !value["artifact_reference"].is_string()
            || value["listener_hash"].get<std::string>().empty()
            || value["artifact_reference"].get<std::string>().empty()
            || (value.contains("hosted_filename") && !value["hosted_filename"].is_string()))
            throw JobError(JobErrorCode::invalid_argument, "Invalid host_artifact input.");
        for (auto it = value.begin(); it != value.end(); ++it)
            if (it.key() != "listener_hash" && it.key() != "artifact_reference" && it.key() != "hosted_filename")
                throw JobError(JobErrorCode::invalid_argument, "Unknown host_artifact field.");
        return nlohmann::json{
            {"listener_hash", value["listener_hash"]},
            {"artifact_reference", value["artifact_reference"]},
            {"hosted_filename", value.value("hosted_filename", std::string{})}}.dump();
    }
    if (operation == "socks_control")
    {
        if (!value.is_object() || !value.contains("action") || !value["action"].is_string()
            || (value.contains("beacon_hash") && !value["beacon_hash"].is_string())
            || value.size() > 2)
            throw JobError(JobErrorCode::invalid_argument, "Invalid socks_control input.");
        for (auto it = value.begin(); it != value.end(); ++it)
            if (it.key() != "action" && it.key() != "beacon_hash")
                throw JobError(JobErrorCode::invalid_argument, "Unknown socks_control field.");
        const std::string action = value["action"].get<std::string>();
        const std::string beaconHash = value.value("beacon_hash", std::string{});
        if ((action != "start" && action != "stop" && action != "bind" && action != "unbind")
            || (action == "bind") != !beaconHash.empty())
            throw JobError(JobErrorCode::invalid_argument, "Invalid SOCKS action or beacon hash.");
        return nlohmann::json{{"action", action}, {"beacon_hash", beaconHash}}.dump();
    }
    if (operation != "session_command")
        throw JobError(JobErrorCode::invalid_argument, "Unknown job operation.");
    if (!value.is_object() || !value.contains("command") || !value["command"].is_string()
        || !value.contains("beacon_hash") || !value["beacon_hash"].is_string()
        || !value.contains("listener_hash") || !value["listener_hash"].is_string()
        || value["command"].get<std::string>().empty()
        || value["beacon_hash"].get<std::string>().empty()
        || value["listener_hash"].get<std::string>().empty())
        throw JobError(JobErrorCode::invalid_argument, "session_command needs command, beacon_hash and listener_hash.");
    // Only the fields used by dispatch are retained, so unknown fields cannot change the hash silently.
    return nlohmann::json{
        {"beacon_hash", value["beacon_hash"]},
        {"command", value["command"]},
        {"listener_hash", value["listener_hash"]}}.dump();
}
} // namespace

JobApplicationService::JobApplicationService(std::shared_ptr<IJobRepository> repository,
    std::size_t maxOutputBytes, SessionCommandDispatcher dispatcher, LocalOperationDispatcher localDispatcher)
    : m_repository(std::move(repository)), m_maxOutputBytes(maxOutputBytes), m_dispatcher(std::move(dispatcher)),
      m_localDispatcher(std::move(localDispatcher))
{
    if (!m_repository || !m_maxOutputBytes)
        throw JobError(JobErrorCode::invalid_argument, "A job repository and positive output limit are required.");
}

JobExecution JobApplicationService::submit(const std::string& jobId, const std::string& operation, const std::string& input,
    const std::string& operatorUsername, const std::string& origin)
{
    if (jobId.empty() || jobId.size() > 128)
        throw JobError(JobErrorCode::invalid_argument, "job_id must contain 1 to 128 bytes.");
    if (operatorUsername.size() > 256 || origin.size() > 512)
        throw JobError(JobErrorCode::invalid_argument, "Job attribution is too long.");
    if (!std::all_of(origin.begin(), origin.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9') || c == ':' || c == '.' || c == '_' || c == '-';
        }))
        throw JobError(JobErrorCode::invalid_argument, "Job origin contains unsupported characters.");
    const std::string normalized = normalize(operation, input);
    JobExecution requested;
    requested.jobId = jobId;
    requested.operation = operation;
    requested.normalizedInput = normalized;
    requested.requestHash = digest(operation, normalized);
    requested.operatorUsername = operatorUsername;
    requested.origin = origin;
    requested.state = "accepted";
    requested.createdAt = nowMillis();
    auto [execution, created] = m_repository->create(requested);
    if (!created)
        return execution;
    notifyCommitted();

    // Commit the handoff state before touching the non-transactional listener queue. On restart,
    // all unfinished jobs become outcome_unknown; the server never silently dispatches twice.
    execution = m_repository->transition(jobId, "accepted", "queued", {}, {}, {});
    notifyCommitted();
    if (operation == "echo")
        return complete(jobId, true, normalized);
    if (operation == "host_artifact" || operation == "socks_control" || operation == "reload_modules")
    {
        try
        {
            const auto result = m_localDispatcher
                ? m_localDispatcher(execution)
                : TeamServerOperationResult{false, "No local operation dispatcher is configured."};
            return complete(jobId, result.ok, result.ok ? result.output : std::string{},
                result.ok ? std::string{} : "operation_failed", result.ok ? std::string{} : result.output);
        }
        catch (const std::exception& error)
        {
            return complete(jobId, false, {}, "operation_failed", error.what());
        }
    }

    try
    {
        const std::string error = m_dispatcher ? m_dispatcher(execution) : "No session command dispatcher is configured.";
        if (!error.empty())
            return complete(jobId, false, {}, "dispatch_failed", error);
    }
    catch (const std::exception& error)
    {
        return complete(jobId, false, {}, "dispatch_failed", error.what());
    }
    return m_repository->get(jobId);
}

JobExecution JobApplicationService::get(const std::string& jobId) const
{
    return m_repository->get(jobId);
}

JobListPage JobApplicationService::list(std::int64_t afterCreatedAt, const std::string& afterJobId, std::size_t limit) const
{
    if (limit == 0 || limit > 500)
        throw JobError(JobErrorCode::invalid_argument, "Page size must be between 1 and 500.");
    return m_repository->list(afterCreatedAt, afterJobId, limit);
}

std::vector<JobEvent> JobApplicationService::events(std::int64_t afterEventId,
    const JobEventFilter& filter, std::size_t limit) const
{
    if (afterEventId < 0 || limit == 0 || limit > 500)
        throw JobError(JobErrorCode::invalid_argument, "Invalid event cursor or page size.");
    if (!filter.state.empty() && filter.state != "accepted" && filter.state != "queued"
        && filter.state != "succeeded" && filter.state != "failed" && filter.state != "outcome_unknown")
        throw JobError(JobErrorCode::invalid_argument, "Unknown state filter.");
    return m_repository->events(afterEventId, filter, limit);
}

JobExecution JobApplicationService::complete(const std::string& jobId, bool success,
    const std::string& output, const std::string& errorCode, const std::string& errorMessage)
{
    const bool tooLarge = output.size() > m_maxOutputBytes;
    const std::string state = success && !tooLarge ? "succeeded" : "failed";
    const std::string code = tooLarge ? "output_too_large" : errorCode;
    const std::string message = tooLarge ? "Output exceeds the configured inline limit." : errorMessage;
    const std::string currentState = m_repository->get(jobId).state;
    JobExecution execution = m_repository->transition(jobId, currentState, state, code, message,
        tooLarge ? std::string{} : output, static_cast<std::int64_t>(output.size()));
    notifyCommitted();
    return execution;
}

bool JobApplicationService::waitForEvents(std::int64_t afterEventId, const JobEventFilter& filter,
    const std::function<bool()>& cancelled, std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lock(m_eventMutex);
    const auto generation = m_generation;
    lock.unlock();
    if (!events(afterEventId, filter, 1).empty())
        return true;
    lock.lock();
    m_eventCondition.wait_for(lock, timeout, [&] { return m_generation != generation || cancelled(); });
    return !cancelled();
}

void JobApplicationService::notifyCommitted()
{
    {
        std::lock_guard<std::mutex> lock(m_eventMutex);
        ++m_generation;
    }
    m_eventCondition.notify_all();
}
