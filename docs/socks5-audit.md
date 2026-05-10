# SOCKS5 Audit

Date: 2026-05-10

Scope: `libs/libSocks5`, `TeamServerSocksService`, and the current beacon tunnel integration.

## Current Contract

- SOCKS version: SOCKS5.
- Method negotiation: no-auth is accepted; username/password code exists.
- Command support: `CONNECT` only.
- Address support: IPv4 only.
- Domain-name and IPv6 targets are intentionally not supported yet. Hostname support remains tracked by TODO item 24.
- Transport model: the local SOCKS server creates a tunnel slot, the TeamServer sends `SO5 init/run/stop` tasks to the bound beacon, and the beacon opens the target socket from its own context.

## Fixes Applied

- Unsupported SOCKS commands now return reply `0x07` (`Command not supported`) instead of closing with a silent EOF.
- Unsupported address types, including hostname `ATYP=0x03`, now return reply `0x08` (`Address type not supported`) instead of a silent EOF.
- Handshake reads now have a bounded timeout so an idle or partial client cannot block the accept loop forever.
- Success replies now encode the bind port in network byte order.
- Library stdout/stderr noise was removed from the normal SOCKS path and SIGPIPE handler.
- `SocksServer` cross-thread state flags are atomic.
- `TestsSocksServer` is now an automated protocol test instead of a manual harness.

## Automated Coverage

- `TestsSocksServer`
  - rejects unsupported auth method with `0xff`
  - accepts no-auth
  - queues IPv4 `CONNECT`
  - returns a valid success reply after `finishHandshake`
  - rejects hostname `CONNECT` with `0x08`
  - rejects non-`CONNECT` commands with `0x07`
- `testsTeamServerSocksService`
  - covers terminal lifecycle: `start`, `bind`, `unbind`, `stop`, duplicate/error paths.
- `scripts/socks5_stress_test.py`
  - remains the live stress tool for bound beacon routes.
  - default mode resolves hostnames locally to IPv4.
  - `--socks-hostname` should now fail explicitly with SOCKS reply `0x08` until item 24 is implemented.

## Residual Risks

- Hostname and IPv6 targets are not implemented. This is the main functional gap and should stay isolated in item 24.
- The TeamServer-to-beacon tunnel is still polling-driven. Throughput and latency depend heavily on beacon sleep and task/result cadence.
- There is no per-tunnel throughput metric, byte counter, queue depth, or timeout surfaced to the operator.
- Buffering is bounded per drain call, but there is no end-to-end backpressure model across local client, TeamServer queue, and beacon socket.
- The TeamServer SOCKS service is single-route today: one local port and one bound beacon at a time.
- Error details are still mostly textual at the terminal layer; typed command/error status would be cleaner once the broader error proto work lands.

## Manual Validation To Keep

1. Start SOCKS and bind a live beacon.
2. Run `curl --socks5 127.0.0.1:1080 http://example.com/ -I`.
3. Run `scripts/socks5_stress_test.py --proxy-host 127.0.0.1 --proxy-port 1080 --url http://example.com/ --requests 300 --concurrency 25 --timeout 15 --expect-status 200`.
4. Run the same stress test with `--socks-hostname` and verify the failure is explicit (`0x08`) rather than `unexpected EOF`.
