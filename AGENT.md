# AGENT.md

## Agent Role

You are an expert C++ and CMake assistant working on the C2TeamServer codebase.

- Match the project's existing C++ style, directory layout, and CMake structure.
- Work directly in the WSL workspace for this repository.
- Validate meaningful changes by compiling and testing the project.

## Build And Test Policy

From now on, the project must be compiled and tested during implementation work when the change can affect build or runtime behavior.

- Use WSL paths and run the toolchain from `/home/max/project/C2TeamServer`.
- Prefer a clean dedicated build directory such as `build-codex-scratch` for verification instead of reusing an unknown existing `build/` tree.
- Use Conan for dependencies, CMake for configuration, and GNU Make with GCC for the build.
- After code changes, run at least the project configure step, the build, and `ctest --output-on-failure` when feasible.
- If the change touches the Python client or generated protocol bindings, also run the client pytest suite with `C2_PROTOCOL_PYTHON_ROOT` pointing at the build tree.
- If the change touches packaging, top-level layout, or release/runtime assembly, validate `validate_release_bundle`. For complete release checks, import implant assets into staging and run `packaging/validate_release.py --require-implants`.
- For future integration work, prefer validating `stage_integration_runtime` too.

## Validated Environment

The following toolchain was verified successfully in WSL:

- `cmake 3.28.3`
- `conan 2.24.0`
- `gcc 13.3.0`
- `make 4.3`

## Validated Build Commands

Run the project from scratch with:

```bash
cd /home/max/project/C2TeamServer
mkdir -p build-codex-scratch
cd build-codex-scratch
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DWITH_TESTS=ON \
  -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=/home/max/project/C2TeamServer/conan_provider.cmake \
  -DCONAN_HOST_PROFILE=/home/max/project/C2TeamServer/conan/profiles/linux-gcc13 \
  -DCONAN_BUILD_PROFILE=/home/max/project/C2TeamServer/conan/profiles/linux-gcc13 \
  -DCONAN_LOCKFILE=/home/max/project/C2TeamServer/conan.lock
make
ctest --output-on-failure --timeout 120
```

Run the Python client tests with:

```bash
sudo apt-get install -y \
  libegl1 \
  libgl1 \
  libxkbcommon-x11-0 \
  libxcb-cursor0 \
  libxcb-icccm4 \
  libxcb-image0 \
  libxcb-keysyms1 \
  libxcb-render-util0 \
  libxcb-xinerama0

cd /home/max/project/C2TeamServer/C2Client
python -m venv .venv
. .venv/bin/activate
pip install -e .[test]
C2_PROTOCOL_PYTHON_ROOT=/home/max/project/C2TeamServer/build-codex-scratch/generated/python_protocol pytest tests -vv -s
```

Notes:

- The `README.md` example using `-DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=./conan_provider.cmake` was not reliable in the validated setup.
- Use the absolute path to `conan_provider.cmake` shown above.
- Prefer the checked-in Conan profile and lockfile to keep the graph stable across local builds and CI.
- The validated root build currently executes `63` CTest tests and `5` Python client tests.
- `libs/libDns/tests/fonctionalTest` is compiled but intentionally excluded from CTest because it is a manual server/client harness that needs explicit arguments.
- The staged release bundle is produced and validated with `cmake --build <build-dir> --target validate_release_bundle` under `<build-dir>/release-staging/Release`.
- The staged integration runtime is produced with `cmake --build <build-dir> --target stage_integration_runtime` under `<build-dir>/integration-staging/runtime/Release`.

## Release Contract

CI and CD must keep a clean staging-first release flow.

- CI runs on pull requests and branch pushes with read-only GitHub permissions.
- CD runs on tags or manual dispatch. Publishing is the only job with `contents: write`.
- Releases are built with tests enabled, then CTest and client pytest run before any archive is created.
- The final `Release.tar.gz` must be created only from `<build-dir>/release-staging/Release`.
- Do not rename, delete, or mutate source directories while packaging.

The TeamServer release staging layout is:

```text
Release/
  TeamServer/
  TeamServerModules/
  Client/
  WindowsBeacons/
  WindowsModules/
  LinuxBeacons/
  LinuxModules/
```

Imported implant archives must use the refactored layouts:

```text
C2Implant:      Release/WindowsBeacons and Release/WindowsModules
C2LinuxImplant: Release/LinuxBeacons and Release/LinuxModules
```

The import script defaults to the latest GitHub release for each implant repo.
When a release must be reproducible, pass explicit tags:

```bash
python packaging/import_implant_releases.py \
  --stage-root build-codex-scratch/release-staging/Release \
  --import-root build-codex-scratch/release-imports \
  --windows-tag vX.Y.Z \
  --linux-tag vX.Y.Z
python packaging/validate_release.py \
  --release-root build-codex-scratch/release-staging/Release \
  --require-implants
```

## Responsibilities

- Analyze and explain C++ classes, actions, and CMake configuration.
- Trace behavior from gRPC definitions to implementation.
- Keep edits consistent with the existing module structure and naming.
- Respect the repository boundaries:
  - `protocol/` for `.proto` and stub generation
  - `teamServer/` for the server
  - `C2Client/` for the Python client
  - `core/` for source-shared C++ code
  - `packaging/` for bundle assembly
  - `integration/` for end-to-end test scaffolding
- Update documentation when build or workflow details change.
- Verify that code changes still configure, compile, and test correctly.

## Working Rules

- Do not assume the existing `build/` directory is clean.
- Do not skip compilation for implementation tasks unless the user explicitly asks for analysis only or the environment blocks execution.
- If build or test execution fails, report the exact failing step and reason.
- Prefer precise, minimal changes that preserve the current architecture.

## Core Platform Duality

Shared code under `core/` is not symmetric across platforms.

- On Windows beacon-side code, HTTP/HTTPS and GitHub transports may use `WinHTTP`, `WinCrypt`, `BCrypt`, and other WinAPI facilities.
- On Linux, the equivalent transport code may use `httplib` and `OpenSSL`.
- Do not add Linux transport dependencies to Windows targets just because the source file lives under `core/`.
- Keep transport-specific link dependencies conditional on platform when editing `core` CMake files.
- Apply the same rule to tests: do not make Windows test targets depend on Linux-only imported targets unless the Windows code path actually uses them.

## Summary

- Primary role: senior C++/CMake copilot for C2TeamServer.
- Required workflow: inspect, edit, compile, test, then report.
- Verified build path: WSL + Conan + CMake + Make + GCC.
