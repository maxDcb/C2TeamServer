# AGENT.md

## Role

Senior C++/CMake assistant for C2TeamServer.

- Keep changes small and aligned with existing structure.
- Compile and test meaningful implementation changes.
- Do not mutate source directories during packaging.
- Do not revert user changes.

## Docs

- Build and tests: [docs/build.md](docs/build.md)
- Release packaging: [docs/release.md](docs/release.md)
- Implant assets: [docs/implants.md](docs/implants.md)
- CI/CD: [docs/ci-cd.md](docs/ci-cd.md)
- Integration runtime: [docs/integration.md](docs/integration.md)

## Minimum Validation

For C++ or CMake changes:

```bash
cmake -S . -B build-codex-scratch \
  -DCMAKE_BUILD_TYPE=Release \
  -DWITH_TESTS=ON \
  -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES="$PWD/conan_provider.cmake" \
  -DCONAN_HOST_PROFILE="$PWD/conan/profiles/linux-gcc13" \
  -DCONAN_BUILD_PROFILE="$PWD/conan/profiles/linux-gcc13" \
  -DCONAN_LOCKFILE="$PWD/conan.lock"

cmake --build build-codex-scratch --config Release --parallel "$(nproc)"
ctest --test-dir build-codex-scratch --build-config Release --output-on-failure --timeout 120
```

For Python client changes:

```bash
C2_PROTOCOL_PYTHON_ROOT="$PWD/build-codex-scratch/generated/python_protocol" \
QT_QPA_PLATFORM=offscreen \
python -m pytest C2Client/tests -vv -s
```

For packaging changes:

```bash
cmake --build build-codex-scratch --target validate_release_bundle --config Release
python packaging/validate_release.py --release-root build-codex-scratch/release-staging/Release
```

For complete release checks:

```bash
python packaging/import_implant_releases.py \
  --stage-root build-codex-scratch/release-staging/Release \
  --import-root build-codex-scratch/release-imports \
  --windows-tag 0.14.0 \
  --linux-tag 0.14.0

python packaging/validate_release.py \
  --release-root build-codex-scratch/release-staging/Release \
  --require-implants
```

## Repo Boundaries

```text
protocol/     .proto and generated gRPC rules
teamServer/   TeamServer runtime
C2Client/     Python client
core/         shared C++ code
packaging/    release assembly and validation
integration/  runtime staging and integration tests
docs/         technical docs
```

## Core Platform Rule

Shared code under `core/` is not symmetric across platforms.

- Windows beacon code may use `WinHTTP`, `WinCrypt`, `BCrypt`, and WinAPI.
- Linux code may use `httplib` and `OpenSSL`.
- Keep platform-specific links conditional.
- Do not add Linux-only dependencies to Windows targets unless the Windows path uses them.
