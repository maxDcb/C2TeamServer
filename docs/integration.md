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

## Operator audit

The client writes `Client.audit.jsonl` in `C2_LOG_DIR` (or its package `logs/`
directory). TeamServer writes `logs/TeamServer.audit.jsonl` from its working
directory. Both contain one JSON object per event with a Unix millisecond
timestamp, action, outcome, and selected target identifiers. Client events
include `client_id`, operator username, and TeamServer endpoint. Server RPC
events include the authenticated actor, `client_id`, and network peer. Match the two
sides using `client_id`, action, target, and `job_id` where available.

The audit covers authentication, session stops, listener changes, job
submissions, TeamServer terminal actions, artifact transfers/deletion, and
credential changes or secret reveals. A `StopSession` server event records both
the requested and resolved beacon/listener hashes. `accepted` means the server
accepted or queued the request; it does not mean the beacon later confirmed
termination. Beacon command results produce a `JobCompleted` audit event with
the final job state; detailed job history remains available through the job API.

Audit records omit command bodies, terminal arguments, passwords, bearer
tokens, credential values, and artifact contents. Audit files are private
(`0600` on Linux). TeamServer rotates its audit log at 10 MiB with five backups;
the client file is append-only and can be managed with the host's log rotation.
The TeamServer audit is active regardless of `LogLevel`. No audit entries are
written by listeners or beacons.

The Sessions panel requests confirmation before every beacon stop. It refreshes
the listener list first and shows any child listeners hosted by the target
beacon. If the list cannot be fetched, the dialog says that child listener
status is unknown. The default choice is **No**; declining sends no stop RPC.
