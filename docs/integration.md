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

## Windows Beacon Flow E2E

The optional `testsWindowsBeaconFlowE2E` test starts TeamServer on Linux and
launches a parent and child `BeaconTcp.exe` on a Windows VM through WinRM. It
runs child beacon jobs, loads `ReversePortForward.dll`, checks an exact echo
through the RPF listener on Windows, and checks an exact echo through SOCKS5
on TeamServer. Both beacons use a zero second sleep. The test reports latency,
goodput, operation loss, and TeamServer/beacon CPU and peak memory usage.

The VM needs WinRM HTTP on port 5985, an account allowed to create processes
and temporary firewall rules, and a working TCP path to the Linux TeamServer.
Install `pywinrm` in the Python interpreter selected by `C2_JOB_TEST_PYTHON`.
Build `BeaconTcp.exe` and `ReversePortForward.dll` for the same Windows
architecture and make the DLL available on the Linux host. For a VirtualBox NAT
adapter, the guest can normally reach a host listener bound to `0.0.0.0` at
`10.0.2.2`; set the addresses for your own network.

```bash
cmake -S . -B build \
  -DC2_WINDOWS_BEACON_REMOTE='C:/Temp/C2Implant-build/beacon/beacon/Release/BeaconTcp.exe' \
  -DC2_WINDOWS_RPF_MODULE="$PWD/build/windows-beacon-flow/ReversePortForward.dll" \
  -DC2_WINDOWS_WINRM_HOST=192.168.56.101 \
  -DC2_WINDOWS_WINRM_USER='windows\root' \
  -DC2_WINDOWS_BEACON_IP=192.168.56.101 \
  -DC2_WINDOWS_SERVER_IP=10.0.2.2 \
  -DC2_WINDOWS_SERVER_BIND_IP=0.0.0.0
cmake --build build --target stage_integration_runtime -j4
read -rs C2_WINRM_PASSWORD; export C2_WINRM_PASSWORD
ctest --test-dir build -R '^testsWindowsBeaconFlowE2E$' --output-on-failure
unset C2_WINRM_PASSWORD
```

`C2_WINDOWS_SERVER_IP` is the address the Windows VM connects to;
`C2_WINDOWS_SERVER_BIND_IP` is the local Linux bind address. If they are the
same, omit the bind option. The RPF listener opens on the Windows child
beacon and forwards to the
Linux echo service at `127.0.0.1` from TeamServer. The test creates a
temporary Windows firewall rule for that listener, scoped to the Linux host,
and removes it during cleanup.
Metrics are saved to `build/windows-beacon-flow-metrics.json`. Increase
`C2_WINDOWS_FLOW_SAMPLES`, `C2_WINDOWS_FLOW_CONCURRENCY`, and
`C2_WINDOWS_FLOW_PAYLOAD_BYTES` at CMake configuration time for load runs.
Optional performance limits use the same `C2_BEACON_FLOW_THRESHOLDS` JSON
file as the Linux test. Keep the password in the environment, outside the CMake
cache and CTest arguments.

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
