# Beacon flows: automated end-to-end and load test

`testsLinuxBeaconFlowE2E` starts an isolated TeamServer runtime on loopback,
launches two real Linux `BeaconTcp` processes, creates a TCP listener on the
first beacon, and connects the second beacon to that child listener. It then
submits jobs through the child route and transfers verified payloads through
reverse port forwarding and SOCKS5. An echo service runs in the same test
process. All processes and temporary runtime files are cleaned up afterward.

The test is registered by CMake on Linux when the Linux implant binary and
`libReversePortForward.so` are present in the sibling `C2LinuxImplant/Release`
tree. The CI workflow checks out and builds those artifacts, aligns its
C2Core revision with TeamServer, passes their paths to CMake, and uploads the
metrics JSON as a workflow artifact. Supply explicit paths when the checkout
is elsewhere:

```sh
cmake -S . -B build \
  -DC2_LINUX_BEACON_BINARY=/path/to/BeaconTcp \
  -DC2_LINUX_RPF_MODULE=/path/to/libReversePortForward.so
cmake --build build --target testsTeamServerRuntimeIntegration -j4
ctest --test-dir build -R testsLinuxBeaconFlowE2E --output-on-failure
```

The default CTest run uses four operations per flow, two concurrent workers,
and 1024 bytes per tunnel operation. It sets both beacons' sleep time and the
TeamServer response polling interval to zero, then writes
`build/beacon-flow-metrics.json`. The server's normal polling interval remains
1000 ms outside this benchmark; override the benchmark with
`--server-poll-ms` and `--beacon-sleep-seconds` when comparing configurations.
Command completion is observed through job events, without a fixed client-side
polling sleep. Zero server polling yields between iterations and can consume
roughly one CPU core. Other internal scheduling and socket waits still apply,
so this measures the zero-beacon-sleep configuration rather than a theoretical
transport-only limit.
For a longer local load run, invoke the same script with `--samples 100`,
`--concurrency 8`, `--payload-bytes 65536`, and an `--output` path. Use the
Python interpreter selected by `C2_JOB_TEST_PYTHON` (it needs `grpcio`).

The JSON reports p50/p95/p99 client round-trip latency, successful operations
per second, acknowledged payload bytes per second, attempts, successes, losses,
concurrency, and the configured sleep/poll intervals. It also records CPU
seconds consumed during the flow phase and peak resident memory for the three
processes. A loss is an
operation that fails or does not return the exact payload before its deadline.
This is an application-level failure rate. TCP packet loss requires a separate
network emulator such as `tc netem`. Loopback results are useful for regressions
and comparative load runs on the same host, not for production network capacity
planning.

The smoke test fails if any operation is lost. For performance comparison,
retain the JSON artifacts from CI and compare p95 latency and goodput against
a baseline measured on the same runner. Set absolute thresholds only after
several baseline runs to avoid host-load flakes.

Pass a JSON file through `--thresholds` or the CMake cache variable
`C2_BEACON_FLOW_THRESHOLDS` to make CTest enforce runner-specific limits. For
example:

```json
{
  "child_jobs": {"max_p95_ms": 2500},
  "reverse_port_forward": {"max_p95_ms": 5000, "min_goodput_Bps": 1000},
  "socks5": {"max_p95_ms": 2000, "min_goodput_Bps": 5000}
}
```

Each flow also accepts `max_loss_rate`; the default is zero. The script writes
its metrics even when a limit fails, so CI can retain the failed run as an
artifact. The SOCKS server currently uses port 1080, so run this CTest case
serially on a host where that port is free.
