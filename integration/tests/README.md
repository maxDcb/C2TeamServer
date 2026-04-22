# Planned Integration Scenarios

This directory now contains the first staged-runtime integration test:

- `TeamServerRuntimeIntegrationTests.cpp`

It is driven from the runtime prepared by `stage_integration_runtime`.

Recommended first scenarios:

1. Python client can import `c2client_protocol` from the staged bundle
2. Python client can authenticate against the staged TeamServer
3. One stable RPC smoke path validates server/client/protocol compatibility
