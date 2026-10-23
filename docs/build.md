# Build And Tests

## Dependencies

```bash
sudo apt-get update
sudo apt-get install -y \
  golang-cfssl \
  libegl1 \
  libgl1 \
  libsmbclient-dev \
  libxkbcommon-x11-0 \
  libxcb-cursor0 \
  libxcb-icccm4 \
  libxcb-image0 \
  libxcb-keysyms1 \
  libxcb-render-util0 \
  libxcb-xinerama0

python3 -m pip install --upgrade "conan==2.24.0"
```

## Configure And Build

```bash
git submodule update --init --recursive

cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DWITH_TESTS=ON \
  -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES="$PWD/conan_provider.cmake" \
  -DCONAN_HOST_PROFILE="$PWD/conan/profiles/linux-gcc13" \
  -DCONAN_BUILD_PROFILE="$PWD/conan/profiles/linux-gcc13" \
  -DCONAN_LOCKFILE="$PWD/conan.lock"

cmake --build build --config Release --parallel "$(nproc)"
```

## CTest

```bash
ctest --test-dir build \
  --build-config Release \
  --output-on-failure \
  --timeout 120
```

Current validated root suite:

```text
78 CTest tests
```

`libs/libDns/tests/fonctionalTest` is built but not registered in CTest. It is a manual server/client harness.

For the TCP listener, socket lifecycle, framing, and concurrent session checks:

```bash
ctest --test-dir build -R '^(TestsSockerHandler|listener_unit_tests|listener_tcp_transport_tests)$' \
  --output-on-failure --timeout 30
```

TCP keeps the existing `<TCP-666>` wire delimiter. Each incomplete frame is
buffered until the delimiter arrives; frames larger than 64 MiB are rejected.

## Client Pytest

The client tests need generated Python protocol bindings from the CMake build.

```bash
cd C2Client
python -m venv .venv
. .venv/bin/activate
pip install -e .[test]

C2_PROTOCOL_PYTHON_ROOT="$PWD/../build/generated/python_protocol" \
QT_QPA_PLATFORM=offscreen \
pytest tests -vv -s
```

Current validated client suite:

```text
206 pytest tests
```

## Durable job API V2

The TeamServer opens the SQLite database at `JobDatabasePath` before serving gRPC.
The default is `../data/jobs.sqlite` relative to the TeamServer runtime directory.
`MaxJobOutputBytes` defaults to `65536`. The server exits with an error if SQLite
cannot open, check, or migrate the file. Preserve the database file together with
its WAL files when backing it up while the server is running.

SQLite is linked through its C API. A system SQLite runtime library is required
for the TeamServer build and runtime. A SQLite development header is used when
available; otherwise the repository's small C declaration shim covers the calls
used here.

Build and test with the commands above. The job-specific checks are:

```bash
cmake --build build --parallel "$(nproc)"
ctest --test-dir build -R '^(testsJobRepository|testsTeamServerListenerSessionService|testsJobRuntimeE2E)$' \
  --output-on-failure --timeout 120
C2_PROTOCOL_PYTHON_ROOT="$PWD/build/generated/python_protocol" \
  QT_QPA_PLATFORM=offscreen \
  C2Client/.venv/bin/python -m pytest C2Client/tests -q
```

The end-to-end test uses a Python interpreter with `grpcio`. CMake selects
`C2Client/.venv/bin/python` if present, then the configured Python interpreter.
Set `-DC2_JOB_TEST_PYTHON=/absolute/path/to/python` during configure to override
this selection. The end-to-end test opens a loopback port.

Use the minimal client with `C2_CERT_PATH`, `C2_USERNAME`, and `C2_PASSWORD` set:

```bash
C2Client/.venv/bin/python -m C2Client.jobs_cli --ip 127.0.0.1 --port 50051 --dev \
  submit echo hello --job-id example-1
C2Client/.venv/bin/python -m C2Client.jobs_cli --ip 127.0.0.1 --port 50051 --dev \
  get example-1
C2Client/.venv/bin/python -m C2Client.jobs_cli --ip 127.0.0.1 --port 50051 --dev \
  watch --cursor-file ./job-cursor.txt
```

For a session command, submit `session_command` with `--beacon-hash` and
`--listener-hash`. A repeated `job_id` with the same request returns the existing
execution; a different request returns gRPC `ALREADY_EXISTS`. An unfinished job
is marked `outcome_unknown` on restart and is never dispatched automatically
again. This avoids an unobserved duplicate when a beacon may already have
received the task. A late beacon result with its job ID can still complete it.

## Client LLM skills

See [assistant-skills.md](assistant-skills.md) for fixed and agentic skills,
client-side recovery, the pinned `agent-core` dependency, and GUI startup.
