#include <chrono>
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
        auto first = application.submit("echo-1", "echo", std::string("a\0b\xff", 4));
        require(first.state == "succeeded", "Echo must succeed");
        require(first.outputInline == std::string("a\0b\xff", 4), "BLOB bytes changed");
        require(first.outputSize == 4, "BLOB size changed");
        auto repeated = application.submit("echo-1", "echo", std::string("a\0b\xff", 4));
        require(repeated.outputInline == first.outputInline, "Idempotent result changed");
        require(application.events(0, {}, 10).size() == 3, "Duplicate submission added events");
        expectError([&] { application.submit("echo-1", "echo", "different"); }, JobErrorCode::conflict);
        expectError([&] { application.submit("bad", "does-not-exist", "x"); }, JobErrorCode::invalid_argument);
    }
    {
        auto repository = std::make_shared<SqliteJobRepository>(temp.path());
        require(repository->get("echo-1").outputInline == std::string("a\0b\xff", 4), "Reopen lost output");
        require(repository->recoverInFlight() == 0, "Completed job recovered");
    }
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
}

void testOutputLimitAndConcurrency()
{
    TempDb temp;
    auto repository = std::make_shared<SqliteJobRepository>(temp.path());
    JobApplicationService application(repository, 3, {});
    auto large = application.submit("large", "echo", "1234");
    require(large.state == "failed" && large.errorCode == "output_too_large", "Output limit not enforced");
    require(large.outputInline.empty(), "Oversize output was stored");
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
}
} // namespace

int main()
{
    try
    {
        testCreateIdempotenceAndReopen();
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
