#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

enum class JobErrorCode { invalid_argument, conflict, not_found, invalid_transition, storage };

class JobError : public std::runtime_error
{
public:
    JobError(JobErrorCode code, const std::string& message) : std::runtime_error(message), m_code(code) {}
    JobErrorCode code() const noexcept { return m_code; }

private:
    JobErrorCode m_code;
};

struct JobExecution
{
    std::string jobId;
    std::string operation;
    std::string normalizedInput;
    std::string requestHash;
    std::string state;
    std::int64_t createdAt = 0;
    std::int64_t queuedAt = 0;
    std::int64_t completedAt = 0;
    std::string errorCode;
    std::string errorMessage;
    std::string outputInline;
    std::int64_t outputSize = 0;
};

struct JobEvent
{
    std::int64_t eventId = 0;
    std::string jobId;
    std::string eventType;
    std::int64_t createdAt = 0;
    std::string payloadJson;
};

struct JobEventFilter
{
    std::string jobId;
    std::string state;
};

struct JobListPage
{
    std::vector<JobExecution> jobs;
    std::int64_t nextCreatedAt = 0;
    std::string nextJobId;
};

class IJobRepository
{
public:
    virtual ~IJobRepository() = default;
    virtual std::pair<JobExecution, bool> create(const JobExecution& execution) = 0;
    virtual JobExecution get(const std::string& jobId) = 0;
    virtual JobListPage list(std::int64_t afterCreatedAt, const std::string& afterJobId, std::size_t limit) = 0;
    virtual std::vector<JobEvent> events(std::int64_t afterEventId, const JobEventFilter& filter, std::size_t limit) = 0;
    virtual JobExecution transition(const std::string& jobId, const std::string& fromState,
        const std::string& toState, const std::string& errorCode, const std::string& errorMessage,
        const std::string& output, std::int64_t observedOutputSize = -1) = 0;
    virtual std::size_t recoverInFlight() = 0;
};
