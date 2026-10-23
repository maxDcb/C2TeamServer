#include "SqliteJobRepository.hpp"

#include <chrono>
#include <filesystem>
#include <limits>
#include <memory>
#include <stdexcept>
#include <utility>

namespace
{
std::int64_t nowMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

[[noreturn]] void fail(sqlite3* db, const std::string& action)
{
    throw JobError(JobErrorCode::storage, action + ": " + (db ? sqlite3_errmsg(db) : "SQLite unavailable"));
}

void run(sqlite3* db, const char* sql)
{
    char* error = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &error) != SQLITE_OK)
    {
        std::string message = error ? error : sqlite3_errmsg(db);
        sqlite3_free(error);
        throw JobError(JobErrorCode::storage, message);
    }
}

class Statement
{
public:
    Statement(sqlite3* db, const char* sql) : m_db(db)
    {
        if (sqlite3_prepare_v2(db, sql, -1, &m_stmt, nullptr) != SQLITE_OK)
            fail(db, "Prepare SQL");
    }
    ~Statement() { sqlite3_finalize(m_stmt); }
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    sqlite3_stmt* get() const { return m_stmt; }
    void text(int index, const std::string& value)
    {
        if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())
            || sqlite3_bind_text(m_stmt, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT) != SQLITE_OK)
            fail(m_db, "Bind text");
    }
    void blob(int index, const std::string& value)
    {
        if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())
            || sqlite3_bind_blob(m_stmt, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT) != SQLITE_OK)
            fail(m_db, "Bind blob");
    }
    void integer(int index, std::int64_t value)
    {
        if (sqlite3_bind_int64(m_stmt, index, value) != SQLITE_OK)
            fail(m_db, "Bind integer");
    }
    int step()
    {
        const int result = sqlite3_step(m_stmt);
        if (result != SQLITE_ROW && result != SQLITE_DONE)
            fail(m_db, "Execute SQL");
        return result;
    }
private:
    sqlite3* m_db;
    sqlite3_stmt* m_stmt = nullptr;
};

class Transaction
{
public:
    explicit Transaction(sqlite3* db) : m_db(db) { run(db, "BEGIN IMMEDIATE"); }
    ~Transaction() { if (!m_committed) sqlite3_exec(m_db, "ROLLBACK", nullptr, nullptr, nullptr); }
    void commit() { run(m_db, "COMMIT"); m_committed = true; }
private:
    sqlite3* m_db;
    bool m_committed = false;
};

std::string columnString(sqlite3_stmt* statement, int index)
{
    const auto* bytes = sqlite3_column_text(statement, index);
    const int size = sqlite3_column_bytes(statement, index);
    return bytes ? std::string(reinterpret_cast<const char*>(bytes), size) : std::string{};
}

std::string columnBlob(sqlite3_stmt* statement, int index)
{
    const void* bytes = sqlite3_column_blob(statement, index);
    const int size = sqlite3_column_bytes(statement, index);
    return bytes && size > 0 ? std::string(static_cast<const char*>(bytes), size) : std::string{};
}

JobExecution readJob(sqlite3_stmt* statement)
{
    JobExecution job;
    job.jobId = columnString(statement, 0);
    job.operation = columnString(statement, 1);
    job.normalizedInput = columnString(statement, 2);
    job.requestHash = columnString(statement, 3);
    job.state = columnString(statement, 4);
    job.createdAt = sqlite3_column_int64(statement, 5);
    job.queuedAt = sqlite3_column_int64(statement, 6);
    job.completedAt = sqlite3_column_int64(statement, 7);
    job.errorCode = columnString(statement, 8);
    job.errorMessage = columnString(statement, 9);
    job.outputInline = columnBlob(statement, 10);
    job.outputSize = sqlite3_column_int64(statement, 11);
    return job;
}

constexpr const char* JobColumns = "job_id,operation,normalized_input,request_hash,state,created_at,queued_at,completed_at,error_code,error_message,output_inline,output_size";

void addEvent(sqlite3* db, const std::string& jobId, const std::string& state)
{
    Statement event(db, "INSERT INTO job_events(job_id,event_type,created_at,payload_json) VALUES(?,?,?,?)");
    event.text(1, jobId);
    event.text(2, state);
    event.integer(3, nowMillis());
    event.text(4, std::string("{\"state\":\"") + state + "\"}");
    event.step();
}

bool allowed(const std::string& from, const std::string& to)
{
    if (from == "accepted") return to == "queued" || to == "failed" || to == "outcome_unknown";
    if (from == "queued") return to == "succeeded" || to == "failed" || to == "outcome_unknown";
    if (from == "outcome_unknown") return to == "succeeded" || to == "failed";
    return false;
}
} // namespace

SqliteJobRepository::SqliteJobRepository(const std::string& path)
{
    if (path.empty() || path == ":memory:" || path.rfind("file:", 0) == 0)
        throw JobError(JobErrorCode::invalid_argument, "A durable SQLite file path is required.");
    std::filesystem::path file(path);
    std::error_code ec;
    if (!file.parent_path().empty())
        std::filesystem::create_directories(file.parent_path(), ec);
    if (ec)
        throw JobError(JobErrorCode::storage, "Cannot create SQLite parent directory: " + ec.message());
    if (sqlite3_open_v2(path.c_str(), &m_db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK)
    {
        const std::string message = m_db ? sqlite3_errmsg(m_db) : "SQLite unavailable";
        if (m_db) sqlite3_close_v2(m_db);
        m_db = nullptr;
        throw JobError(JobErrorCode::storage, "Cannot open SQLite database: " + message);
    }
    try
    {
        auto pragma = [this](const char* sql) {
            Statement statement(m_db, sql);
            if (statement.step() != SQLITE_ROW) fail(m_db, "Read PRAGMA");
            return columnString(statement.get(), 0);
        };
        run(m_db, "PRAGMA busy_timeout=5000");
        if (pragma("PRAGMA journal_mode=WAL") != "wal")
            throw JobError(JobErrorCode::storage, "SQLite WAL mode was not enabled.");
        run(m_db, "PRAGMA foreign_keys=ON");
        if (pragma("PRAGMA foreign_keys") != "1")
            throw JobError(JobErrorCode::storage, "SQLite foreign keys were not enabled.");
        run(m_db, "PRAGMA synchronous=FULL");
        if (pragma("PRAGMA synchronous") != "2")
            throw JobError(JobErrorCode::storage, "SQLite synchronous FULL was not enabled.");
        if (pragma("PRAGMA quick_check") != "ok")
            throw JobError(JobErrorCode::storage, "SQLite quick_check failed.");

        Transaction migration(m_db);
        run(m_db, "CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)");
        Statement version(m_db, "SELECT COALESCE(MAX(version),0) FROM schema_migrations");
        if (version.step() != SQLITE_ROW) fail(m_db, "Read schema version");
        const auto currentVersion = sqlite3_column_int64(version.get(), 0);
        if (currentVersion > 1)
            throw JobError(JobErrorCode::storage, "Database schema is newer than this server.");
        if (currentVersion == 0)
        {
            run(m_db, "CREATE TABLE job_executions("
                "job_id TEXT PRIMARY KEY, operation TEXT NOT NULL, normalized_input TEXT NOT NULL,"
                "request_hash TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN "
                "('accepted','queued','succeeded','failed','outcome_unknown')) ,"
                "created_at INTEGER NOT NULL, queued_at INTEGER, completed_at INTEGER,"
                "error_code TEXT, error_message TEXT, output_inline BLOB, output_size INTEGER NOT NULL DEFAULT 0)");
            run(m_db, "CREATE TABLE job_events("
                "event_id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL,"
                "event_type TEXT NOT NULL, created_at INTEGER NOT NULL,"
                "payload_json TEXT NOT NULL DEFAULT '{}',"
                "FOREIGN KEY(job_id) REFERENCES job_executions(job_id))");
            run(m_db, "CREATE INDEX idx_job_executions_created ON job_executions(created_at,job_id)");
            run(m_db, "CREATE INDEX idx_job_events_job ON job_events(job_id,event_id)");
            run(m_db, "CREATE INDEX idx_job_events_type ON job_events(event_type,event_id)");
            Statement record(m_db, "INSERT INTO schema_migrations(version,applied_at) VALUES(1,?)");
            record.integer(1, nowMillis());
            record.step();
        }
        migration.commit();
        if (pragma("PRAGMA quick_check") != "ok")
            throw JobError(JobErrorCode::storage, "SQLite quick_check failed after migration.");
    }
    catch (...)
    {
        sqlite3_close_v2(m_db);
        m_db = nullptr;
        throw;
    }
}

SqliteJobRepository::~SqliteJobRepository()
{
    if (m_db) sqlite3_close_v2(m_db);
}

void SqliteJobRepository::execute(const char* sql) { run(m_db, sql); }

JobExecution SqliteJobRepository::getUnlocked(const std::string& jobId)
{
    Statement query(m_db, "SELECT job_id,operation,normalized_input,request_hash,state,created_at,queued_at,completed_at,error_code,error_message,output_inline,output_size FROM job_executions WHERE job_id=?");
    query.text(1, jobId);
    if (query.step() != SQLITE_ROW)
        throw JobError(JobErrorCode::not_found, "Job not found.");
    return readJob(query.get());
}

JobExecution SqliteJobRepository::get(const std::string& jobId)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return getUnlocked(jobId);
}

std::pair<JobExecution, bool> SqliteJobRepository::create(const JobExecution& execution)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    Transaction transaction(m_db);
    Statement insert(m_db, "INSERT INTO job_executions(job_id,operation,normalized_input,request_hash,state,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(job_id) DO NOTHING");
    insert.text(1, execution.jobId);
    insert.text(2, execution.operation);
    insert.text(3, execution.normalizedInput);
    insert.text(4, execution.requestHash);
    insert.text(5, "accepted");
    insert.integer(6, execution.createdAt);
    insert.step();
    const bool created = sqlite3_changes(m_db) == 1;
    if (created) addEvent(m_db, execution.jobId, "accepted");
    JobExecution result = getUnlocked(execution.jobId);
    if (!created && result.requestHash != execution.requestHash)
        throw JobError(JobErrorCode::conflict, "job_id was already used for a different request.");
    transaction.commit();
    return {result, created};
}

JobListPage SqliteJobRepository::list(std::int64_t afterCreatedAt, const std::string& afterJobId, std::size_t limit)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    Statement query(m_db, "SELECT job_id,operation,normalized_input,request_hash,state,created_at,queued_at,completed_at,error_code,error_message,output_inline,output_size FROM job_executions WHERE (created_at>? OR (created_at=? AND job_id>?)) ORDER BY created_at,job_id LIMIT ?");
    query.integer(1, afterCreatedAt);
    query.integer(2, afterCreatedAt);
    query.text(3, afterJobId);
    query.integer(4, static_cast<std::int64_t>(limit));
    JobListPage page;
    while (query.step() == SQLITE_ROW)
        page.jobs.push_back(readJob(query.get()));
    if (!page.jobs.empty())
    {
        page.nextCreatedAt = page.jobs.back().createdAt;
        page.nextJobId = page.jobs.back().jobId;
    }
    return page;
}

std::vector<JobEvent> SqliteJobRepository::events(std::int64_t afterEventId, const JobEventFilter& filter, std::size_t limit)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    Statement query(m_db, "SELECT event_id,job_id,event_type,created_at,payload_json FROM job_events WHERE event_id>? AND (?='' OR job_id=?) AND (?='' OR event_type=?) ORDER BY event_id LIMIT ?");
    query.integer(1, afterEventId);
    query.text(2, filter.jobId);
    query.text(3, filter.jobId);
    query.text(4, filter.state);
    query.text(5, filter.state);
    query.integer(6, static_cast<std::int64_t>(limit));
    std::vector<JobEvent> result;
    while (query.step() == SQLITE_ROW)
    {
        JobEvent event;
        event.eventId = sqlite3_column_int64(query.get(), 0);
        event.jobId = columnString(query.get(), 1);
        event.eventType = columnString(query.get(), 2);
        event.createdAt = sqlite3_column_int64(query.get(), 3);
        event.payloadJson = columnString(query.get(), 4);
        result.push_back(std::move(event));
    }
    return result;
}

JobExecution SqliteJobRepository::transition(const std::string& jobId, const std::string& fromState,
    const std::string& toState, const std::string& errorCode, const std::string& errorMessage,
    const std::string& output)
{
    if (!allowed(fromState, toState))
        throw JobError(JobErrorCode::invalid_transition, "Illegal job state transition.");
    std::lock_guard<std::mutex> lock(m_mutex);
    Transaction transaction(m_db);
    Statement update(m_db, "UPDATE job_executions SET state=?,queued_at=CASE WHEN ?='queued' THEN ? ELSE queued_at END,completed_at=CASE WHEN ? IN ('succeeded','failed','outcome_unknown') THEN ? ELSE completed_at END,error_code=?,error_message=?,output_inline=?,output_size=? WHERE job_id=? AND state=?");
    update.text(1, toState);
    update.text(2, toState);
    update.integer(3, nowMillis());
    update.text(4, toState);
    update.integer(5, nowMillis());
    update.text(6, errorCode);
    update.text(7, errorMessage);
    update.blob(8, output);
    update.integer(9, static_cast<std::int64_t>(output.size()));
    update.text(10, jobId);
    update.text(11, fromState);
    update.step();
    if (sqlite3_changes(m_db) != 1)
    {
        // Distinguish absent jobs from stale or duplicate transitions.
        try { getUnlocked(jobId); }
        catch (const JobError& error) { if (error.code() == JobErrorCode::not_found) throw; }
        throw JobError(JobErrorCode::invalid_transition, "Job is no longer in the expected state.");
    }
    addEvent(m_db, jobId, toState);
    JobExecution result = getUnlocked(jobId);
    transaction.commit();
    return result;
}

std::size_t SqliteJobRepository::recoverInFlight()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    Transaction transaction(m_db);
    Statement query(m_db, "SELECT job_id FROM job_executions WHERE state IN ('accepted','queued') ORDER BY job_id");
    std::vector<std::string> ids;
    while (query.step() == SQLITE_ROW)
        ids.push_back(columnString(query.get(), 0));
    for (const auto& id : ids)
    {
        Statement update(m_db, "UPDATE job_executions SET state='outcome_unknown',completed_at=?,error_code='server_restarted',error_message='Delivery or completion could not be established after restart.' WHERE job_id=? AND state IN ('accepted','queued')");
        update.integer(1, nowMillis());
        update.text(2, id);
        update.step();
        if (sqlite3_changes(m_db) == 1) addEvent(m_db, id, "outcome_unknown");
    }
    transaction.commit();
    return ids.size();
}
