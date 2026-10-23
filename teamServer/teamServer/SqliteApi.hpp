#pragma once

// Development environments without the SQLite SDK can still link the platform's
// SQLite C runtime. These are the public C declarations used by this project.
#if __has_include(<sqlite3.h>)
#include <sqlite3.h>
#else
#include <cstdint>
extern "C" {
struct sqlite3;
struct sqlite3_stmt;
using sqlite3_int64 = long long;
using sqlite3_callback = int (*)(void*, int, char**, char**);
using sqlite3_destructor_type = void (*)(void*);
int sqlite3_open_v2(const char*, sqlite3**, int, const char*);
int sqlite3_close_v2(sqlite3*);
const char* sqlite3_errmsg(sqlite3*);
int sqlite3_exec(sqlite3*, const char*, sqlite3_callback, void*, char**);
void sqlite3_free(void*);
int sqlite3_prepare_v2(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
int sqlite3_finalize(sqlite3_stmt*);
int sqlite3_step(sqlite3_stmt*);
int sqlite3_bind_text(sqlite3_stmt*, int, const char*, int, sqlite3_destructor_type);
int sqlite3_bind_blob(sqlite3_stmt*, int, const void*, int, sqlite3_destructor_type);
int sqlite3_bind_int64(sqlite3_stmt*, int, sqlite3_int64);
const unsigned char* sqlite3_column_text(sqlite3_stmt*, int);
const void* sqlite3_column_blob(sqlite3_stmt*, int);
int sqlite3_column_bytes(sqlite3_stmt*, int);
sqlite3_int64 sqlite3_column_int64(sqlite3_stmt*, int);
int sqlite3_changes(sqlite3*);
sqlite3_int64 sqlite3_last_insert_rowid(sqlite3*);
}
#define SQLITE_OK 0
#define SQLITE_ROW 100
#define SQLITE_DONE 101
#define SQLITE_OPEN_READWRITE 0x00000002
#define SQLITE_OPEN_CREATE 0x00000004
#define SQLITE_OPEN_FULLMUTEX 0x00010000
#define SQLITE_TRANSIENT reinterpret_cast<sqlite3_destructor_type>(-1)
#endif
