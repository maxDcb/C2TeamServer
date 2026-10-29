#include <chrono>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>

#include "JobApplicationService.hpp"
#include "SqliteJobRepository.hpp"

namespace fs = std::filesystem;

namespace
{
void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

template<typename Function>
void expectError(Function function, JobErrorCode code)
{
    try { function(); }
    catch (const JobError& error) { require(error.code() == code, "Wrong job error code"); return; }
    throw std::runtime_error("Expected job error");
}

struct TempDb
{
    fs::path root = fs::temp_directory_path() /
        ("c2-jobs-" + std::to_string(::getpid()) + "-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    TempDb() { fs::create_directories(root); }
    ~TempDb() { std::error_code error; fs::remove_all(root, error); }
    std::string path() const { return (root / "jobs.sqlite").string(); }
};

void testCreateIdempotenceAndReopen()
{
    TempDb temp;
    {
        auto repository = std::make_shared<SqliteJobRepository>(temp.path());
        JobApplicationService application(repository, 65536, {});
        auto first = application.submit("echo-1", "echo", std::string("a\0b\xff", 4),
            "operator-one", "hook:sample:invocation-one");
        require(first.state == "succeeded", "Echo must succeed");
        require(first.outputInline == std::string("a\0b\xff", 4), "BLOB bytes changed");
        require(first.outputSize == 4, "BLOB size changed");
        require(first.operatorUsername == "operator-one" && first.origin == "hook:sample:invocation-one",
            "Job attribution was not persisted");
        auto repeated = application.submit("echo-1", "echo", std::string("a\0b\xff", 4));
        require(repeated.outputInline == first.outputInline, "Idempotent result changed");
        require(application.events(0, {}, 10).size() == 3, "Duplicate submission added events");
        expectError([&] { application.submit("echo-1", "echo", "different"); }, JobErrorCode::conflict);
        expectError([&] { application.submit("invalid-origin", "echo", "x", "operator", "hook:secret\nvalue"); },
            JobErrorCode::invalid_argument);
        expectError([&] { application.submit("bad", "does-not-exist", "x"); }, JobErrorCode::invalid_argument);
    }
    {
        auto repository = std::make_shared<SqliteJobRepository>(temp.path());
        require(repository->get("echo-1").outputInline == std::string("a\0b\xff", 4), "Reopen lost output");
        require(repository->get("echo-1").origin == "hook:sample:invocation-one", "Reopen lost origin");
        require(repository->recoverInFlight() == 0, "Completed job recovered");
    }
}

void testDurableLocalOperations()
{
    TempDb temp;
    const std::string hostInput = R"({"listener_hash":"listener","artifact_reference":"artifact","hosted_filename":"file.bin"})";
    {
        auto repository = std::make_shared<SqliteJobRepository>(temp.path());
        int calls = 0;
        JobApplicationService application(repository, 65536, {},
            [&](const JobExecution& job) -> TeamServerOperationResult
            {
                ++calls;
                require(job.operation == "host_artifact", "Wrong local operation dispatched");
                return {true, "https://example.test/file.bin"};
            });
        const auto first = application.submit("host-1", "host_artifact", hostInput, "operator", "assistant");
        require(first.state == "succeeded", "Local operation did not succeed");
        require(first.outputInline == "https://example.test/file.bin", "Local output was lost");
        const auto repeated = application.submit("host-1", "host_artifact", hostInput);
        require(repeated.outputInline == first.outputInline && calls == 1,
            "Duplicate local operation was dispatched");
        expectError([&] { application.submit("host-1", "host_artifact",
            R"({"listener_hash":"other","artifact_reference":"artifact"})"); }, JobErrorCode::conflict);
        expectError([&] { application.submit("invalid-bind", "socks_control",
            R"({"action":"bind"})"); }, JobErrorCode::invalid_argument);
    }
    {
        auto repository = std::make_shared<SqliteJobRepository>(temp.path());
        JobApplicationService application(repository, 65536, {});
        const auto recovered = application.submit("host-1", "host_artifact", hostInput);
        require(recovered.state == "succeeded" && recovered.outputInline == "https://example.test/file.bin",
            "Completed local operation was lost after restart");
    }
}

void testSessionHistorySurvivesRetirementAndRestart()
{
    TempDb temp;
    teamserverapi::Session session;
    session.set_beacon_hash("beacon-one");
    session.set_listener_hash("listener-one");
    session.set_hostname("host-one");
    session.set_last_proof_of_life("2.0");
    session.set_state(teamserverapi::SESSION_STATE_STOPPED);
    session.set_killed(true);
    {
        SqliteJobRepository repository(temp.path());
        repository.syncSessions({session});
        const auto active = repository.listSessions();
        require(active.size() == 1 && !active.front().archived(), "Live session was not stored");
        require(active.front().last_seen_at_ms() > 0, "Last contact timestamp was not recorded");
        repository.syncSessions({});
        const auto archived = repository.listSessions();
        require(archived.size() == 1 && archived.front().archived(), "Retired session vanished");
        require(archived.front().archived_at_ms() > 0, "Retirement timestamp was not recorded");
    }
    {
        SqliteJobRepository repository(temp.path());
        const auto archived = repository.listSessions();
        require(archived.size() == 1 && archived.front().archived(), "Restart lost session history");
        require(archived.front().state() == teamserverapi::SESSION_STATE_STOPPED,
            "Restart lost the confirmed stop state");
        session.set_state(teamserverapi::SESSION_STATE_RUNNING);
        session.set_killed(false);
        repository.syncSessions({session});
        require(!repository.listSessions().front().archived(), "Returning route was not reactivated");
    }
}

void testExistingJobDatabaseGainsSessionHistory()
{
    TempDb temp;
    {
        auto repository = std::make_shared<SqliteJobRepository>(temp.path());
        JobApplicationService application(repository, 65536, {});
        application.submit("legacy-job", "echo", "saved");
    }
    sqlite3* db = nullptr;
    require(sqlite3_open_v2(temp.path().c_str(), &db, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK,
        "Open legacy SQLite failed");
    char* error = nullptr;
    require(sqlite3_exec(db,
        "DROP TABLE session_history;"
        "DELETE FROM schema_migrations WHERE version>=2;",
        nullptr, nullptr, &error) == SQLITE_OK, "Simulate version 1 schema failed");
    sqlite3_close_v2(db);
    SqliteJobRepository upgraded(temp.path());
    require(upgraded.get("legacy-job").outputInline == "saved", "Migration lost existing jobs");
    require(upgraded.listSessions().empty(), "Migration did not create an empty session archive");
}

void testTransitionsAndCursor()
{
    TempDb temp;
    SqliteJobRepository repository(temp.path());
    JobExecution one;
    one.jobId = "one"; one.operation = "echo"; one.normalizedInput = "a";
    one.requestHash = "hash-1"; one.createdAt = 100;
    require(repository.create(one).second, "Initial create failed");
    one.jobId = "two"; one.requestHash = "hash-2"; one.createdAt = 100;
    require(repository.create(one).second, "Second create failed");
    auto page1 = repository.list(0, "", 1);
    require(page1.jobs.size() == 1 && page1.jobs[0].jobId == "one", "First list page incorrect");
    auto page2 = repository.list(page1.nextCreatedAt, page1.nextJobId, 1);
    require(page2.jobs.size() == 1 && page2.jobs[0].jobId == "two", "Second list page incorrect");
    auto events1 = repository.events(0, {}, 1);
    require(events1.size() == 1, "First event page incorrect");
    auto events2 = repository.events(events1[0].eventId, {}, 1);
    require(events2.size() == 1 && events2[0].eventId > events1[0].eventId, "Event order incorrect");
    expectError([&] { repository.transition("one", "accepted", "succeeded", {}, {}, {}); }, JobErrorCode::invalid_transition);
    require(repository.events(0, {}, 10).size() == 2, "Rejected transition added event");
    repository.transition("one", "accepted", "queued", {}, {}, {});
    repository.transition("one", "queued", "succeeded", {}, {}, std::string("\0\xff", 2));
    expectError([&] { repository.transition("one", "queued", "failed", {}, {}, {}); }, JobErrorCode::invalid_transition);
    require(repository.get("one").outputInline == std::string("\0\xff", 2), "Transition lost bytes");
    JobEventFilter filter; filter.state = "queued";
    require(repository.events(0, filter, 10).size() == 1, "Historical state filter incorrect");
    require(repository.recoverInFlight() == 1, "Unfinished job was not recovered");
    require(repository.get("two").state == "outcome_unknown", "Recovery state incorrect");
    auto shared = std::shared_ptr<IJobRepository>(&repository, [](IJobRepository*) {});
    JobApplicationService application(shared, 65536, {});
    auto late = application.complete("two", true, std::string("late\0result", 11));
    require(late.state == "succeeded" && late.outputInline == std::string("late\0result", 11),
        "Late result did not resolve outcome_unknown");
}

void testOutputLimitAndConcurrency()
{
    TempDb temp;
    auto repository = std::make_shared<SqliteJobRepository>(temp.path());
    JobApplicationService application(repository, 3, {});
    auto large = application.submit("large", "echo", "1234");
    require(large.state == "succeeded", "Large output incorrectly failed the job");
    require(repository->get("large").outputInline == "1234", "Large output was not retained");
    require(large.outputSize == 4, "Large output length was not recorded");
    std::thread writer([&] {
        for (int i = 0; i < 30; ++i)
            application.submit("concurrent-" + std::to_string(i), "echo", "ok");
    });
    std::int64_t cursor = 0;
    std::size_t received = 0;
    while (received < 90)
    {
        auto events = application.events(cursor, {}, 7);
        for (const auto& event : events)
        {
            require(event.eventId > cursor, "Concurrent cursor did not advance");
            cursor = event.eventId;
            ++received;
        }
        if (events.empty()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    writer.join();
    require(application.events(0, {}, 500).size() == 93, "Concurrent events missing");
    const std::string biggerThanFormerLimit(128 * 1024, 'x');
    auto veryLarge = application.submit("very-large", "echo", biggerThanFormerLimit);
    require(veryLarge.state == "succeeded", "Output beyond the former 64 KiB limit failed");
    require(repository->get("very-large").outputInline == biggerThanFormerLimit,
            "Output beyond the former 64 KiB limit was not stored intact");
    const auto chunk = application.outputChunk("very-large", 65536, 4096);
    require(chunk.totalSize == static_cast<std::int64_t>(biggerThanFormerLimit.size())
            && chunk.data == biggerThanFormerLimit.substr(65536, 4096),
            "Large output chunk was not read intact");

    std::atomic<int> dispatches{0};
    JobApplicationService sessions(repository, 65536, [&](const JobExecution&) {
        ++dispatches;
        return std::string{};
    });
    const std::string request = R"({"command":"whoami","beacon_hash":"beacon","listener_hash":"listener"})";
    std::thread first([&] { sessions.submit("same-job", "session_command", request); });
    std::thread second([&] { sessions.submit("same-job", "session_command", request); });
    first.join(); second.join();
    require(dispatches == 1, "Concurrent duplicate dispatched twice");
}

void testAtomicityAndStartupFailures()
{
    TempDb temp;
    SqliteJobRepository repository(temp.path());
    JobExecution job;
    job.jobId = "rollback"; job.operation = "echo"; job.normalizedInput = "x";
    job.requestHash = "hash"; job.createdAt = 1;
    repository.create(job);
    repository.transition("rollback", "accepted", "queued", {}, {}, {});
    sqlite3* db = nullptr;
    require(sqlite3_open_v2(temp.path().c_str(), &db, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK, "Open test SQLite failed");
    char* error = nullptr;
    require(sqlite3_exec(db, "CREATE TRIGGER block_success BEFORE INSERT ON job_events WHEN NEW.event_type='succeeded' BEGIN SELECT RAISE(ABORT,'blocked'); END", nullptr, nullptr, &error) == SQLITE_OK, "Trigger creation failed");
    sqlite3_close_v2(db);
    expectError([&] { repository.transition("rollback", "queued", "succeeded", {}, {}, "ok"); }, JobErrorCode::storage);
    require(repository.get("rollback").state == "queued", "State committed without event");
    require(repository.events(0, {}, 10).size() == 2, "Event inserted despite rollback");
    expectError([&] { SqliteJobRepository invalid(":memory:"); }, JobErrorCode::invalid_argument);
    auto corrupt = temp.root / "corrupt.sqlite";
    std::ofstream file(corrupt, std::ios::binary); file << "not a database"; file.close();
    expectError([&] { SqliteJobRepository invalid(corrupt.string()); }, JobErrorCode::storage);
    auto directory = temp.root / "directory";
    fs::create_directory(directory);
    expectError([&] { SqliteJobRepository invalid(directory.string()); }, JobErrorCode::storage);

    auto future = temp.root / "future.sqlite";
    sqlite3* futureDb = nullptr;
    require(sqlite3_open_v2(future.string().c_str(), &futureDb,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK, "Open future SQLite failed");
    require(sqlite3_exec(futureDb,
        "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);"
        "INSERT INTO schema_migrations(version,applied_at) VALUES(4,1);",
        nullptr, nullptr, &error) == SQLITE_OK, "Create future schema failed");
    sqlite3_close_v2(futureDb);
    expectError([&] { SqliteJobRepository invalid(future.string()); }, JobErrorCode::storage);
}
} // namespace

int main()
{
    try
    {
        testCreateIdempotenceAndReopen();
        testDurableLocalOperations();
        testSessionHistorySurvivesRetirementAndRestart();
        testExistingJobDatabaseGainsSessionHistory();
        testTransitionsAndCursor();
        testOutputLimitAndConcurrency();
        testAtomicityAndStartupFailures();
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
