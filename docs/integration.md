# Integration Runtime

## Stage Runtime

```bash
cmake --build build \
  --target stage_integration_runtime \
  --config Release
```

Output:

```text
build/integration-staging/runtime/Release
```

## Validate Expected Files

```bash
test -x build/integration-staging/runtime/Release/TeamServer/TeamServer
test -f build/integration-staging/runtime/Release/Client/c2client_protocol/TeamServerApi_pb2.py
```

## Run Integration Tests

```bash
ctest --test-dir build \
  --build-config Release \
  --output-on-failure \
  --timeout 120 \
  -R testsTeamServerRuntimeIntegration
```

## Current Coverage

```text
TeamServer startup
gRPC authentication
stable empty-state RPCs
```
