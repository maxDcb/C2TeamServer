#pragma once

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>

#include "JobDomain.hpp"
#include "TeamServerOperationResult.hpp"

class JobApplicationService
{
public:
    using SessionCommandDispatcher = std::function<std::string(const JobExecution&)>;
    using LocalOperationDispatcher = std::function<TeamServerOperationResult(const JobExecution&)>;

    JobApplicationService(std::shared_ptr<IJobRepository> repository, std::size_t maxOutputBytes,
        SessionCommandDispatcher dispatcher, LocalOperationDispatcher localDispatcher = {});

    JobExecution submit(const std::string& jobId, const std::string& operation, const std::string& input,
        const std::string& operatorUsername = {}, const std::string& origin = {});
    JobExecution get(const std::string& jobId) const;
    JobOutputChunk outputChunk(const std::string& jobId, std::size_t offset, std::size_t maxBytes) const;
    std::size_t outputPreviewBytes() const { return m_maxOutputBytes; }
    JobListPage list(std::int64_t afterCreatedAt, const std::string& afterJobId, std::size_t limit) const;
    std::vector<JobEvent> events(std::int64_t afterEventId, const JobEventFilter& filter, std::size_t limit) const;
    JobExecution complete(const std::string& jobId, bool success, const std::string& output,
        const std::string& errorCode = {}, const std::string& errorMessage = {});
    bool waitForEvents(std::int64_t afterEventId, const JobEventFilter& filter,
        const std::function<bool()>& cancelled, std::chrono::milliseconds timeout);

private:
    void notifyCommitted();
    std::shared_ptr<IJobRepository> m_repository;
    std::size_t m_maxOutputBytes;
    SessionCommandDispatcher m_dispatcher;
    LocalOperationDispatcher m_localDispatcher;
    std::mutex m_eventMutex;
    std::condition_variable m_eventCondition;
    std::uint64_t m_generation = 0;
};
