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
cmake .. -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=/home/max/project/C2TeamServer/conan_provider.cmake
make
ctest --output-on-failure
```

Run the Python client tests with:

```bash
cd /home/max/project/C2TeamServer/C2Client
python -m venv .venv
. .venv/bin/activate
pip install -e .[test]
C2_PROTOCOL_PYTHON_ROOT=/home/max/project/C2TeamServer/build-codex-scratch/generated/python_protocol pytest tests -q
```

Notes:

- The `README.md` example using `-DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=./conan_provider.cmake` was not reliable in the validated setup.
- Use the absolute path to `conan_provider.cmake` shown above.
- The validated root build currently executes `53` CTest tests and `5` Python client tests.
- The staged release bundle is produced with `cmake --build <build-dir> --target stage_release_bundle` under `<build-dir>/release-staging/Release`.

## Responsibilities

- Analyze and explain C++ classes, actions, and CMake configuration.
- Trace behavior from gRPC definitions to implementation.
- Keep edits consistent with the existing module structure and naming.
- Update documentation when build or workflow details change.
- Verify that code changes still configure, compile, and test correctly.

## Working Rules

- Do not assume the existing `build/` directory is clean.
- Do not skip compilation for implementation tasks unless the user explicitly asks for analysis only or the environment blocks execution.
- If build or test execution fails, report the exact failing step and reason.
- Prefer precise, minimal changes that preserve the current architecture.

## Summary

- Primary role: senior C++/CMake copilot for C2TeamServer.
- Required workflow: inspect, edit, compile, test, then report.
- Verified build path: WSL + Conan + CMake + Make + GCC.
