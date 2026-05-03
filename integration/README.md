# Integration

This directory is the boundary for end-to-end and contract-style integration
tests. It now provides both a stable runtime staging target and a first
TeamServer smoke test that exercises the staged runtime through real gRPC.

## Current Contract

- Source of truth for the test runtime: `build/integration-staging/runtime/Release`
- Preparation target: `cmake --build <build-dir> --target stage_integration_runtime`
- First integration test: `testsTeamServerRuntimeIntegration`
- Inputs:
  - `stage_release_bundle`
  - TeamServer binary and runtime config
  - TeamServer modules
  - Python client sources
  - generated `c2client_protocol` package

## Current Coverage

`testsTeamServerRuntimeIntegration` copies the staged runtime to a temporary
directory, rewrites the gRPC port, starts the real TeamServer binary, performs
an authenticated gRPC round-trip, and verifies stable empty-state RPCs:

- `Authenticate`
- `ListListeners`
- `ListSessions`

## Next Step

The next integration-test phase should extend `integration/tests/` around:

- client transport/auth handshake through the Python client package
- a small gRPC contract smoke test beyond the empty-state RPCs
- one release-bundle smoke test to validate the packaged layout

The goal is to make integration tests run against the same staged runtime that
the release pipeline assembles, so packaging regressions and protocol drift are
caught before release.
