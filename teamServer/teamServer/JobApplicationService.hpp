#pragma once

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>

#include "JobDomain.hpp"

class JobApplicationService
{
public:
    using SessionCommandDispatcher = std::function<std::string(const JobExecution&)>;

    JobApplicationService(std::shared_ptr<IJobRepository> repository, std::size_t maxOutputBytes,
        SessionCommandDispatcher dispatcher);

    JobExecution submit(const std::string& jobId, const std::string& operation, const std::string& input,
        const std::string& operatorUsername = {}, const std::string& origin = {});
    JobExecution get(const std::string& jobId) const;
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
    std::mutex m_eventMutex;
    std::condition_variable m_eventCondition;
    std::uint64_t m_generation = 0;
};
