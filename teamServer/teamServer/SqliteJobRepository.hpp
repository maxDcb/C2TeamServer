#pragma once

#include <mutex>
#include <string>
#include <vector>

#include "JobDomain.hpp"
#include "SqliteApi.hpp"
#include "TeamServerApi.pb.h"

class SqliteJobRepository final : public IJobRepository
{
public:
    explicit SqliteJobRepository(const std::string& path);
    ~SqliteJobRepository() override;
    SqliteJobRepository(const SqliteJobRepository&) = delete;
    SqliteJobRepository& operator=(const SqliteJobRepository&) = delete;

    std::pair<JobExecution, bool> create(const JobExecution& execution) override;
    JobExecution get(const std::string& jobId) override;
    JobOutputChunk outputChunk(const std::string& jobId, std::size_t offset, std::size_t maxBytes) override;
    JobListPage list(std::int64_t afterCreatedAt, const std::string& afterJobId, std::size_t limit) override;
    std::vector<JobEvent> events(std::int64_t afterEventId, const JobEventFilter& filter, std::size_t limit) override;
    JobExecution transition(const std::string& jobId, const std::string& fromState,
        const std::string& toState, const std::string& errorCode, const std::string& errorMessage,
        const std::string& output, std::int64_t observedOutputSize = -1) override;
    std::size_t recoverInFlight() override;
    void syncSessions(const std::vector<teamserverapi::Session>& sessions);
    std::vector<teamserverapi::Session> listSessions();

private:
    JobExecution getUnlocked(const std::string& jobId);
    void execute(const char* sql);
    sqlite3* m_db = nullptr;
    std::mutex m_mutex;
};
