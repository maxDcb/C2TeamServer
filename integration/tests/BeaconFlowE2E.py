"""Loopback end-to-end and load measurements for a real Linux beacon chain.

The result is JSON. A lost operation means no matching application response arrived
before the deadline; TCP packet loss is intentionally not inferred from this value.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import socketserver
import statistics
import subprocess
import sys
import tempfile
import time
import uuid


def reserve_ports(count: int) -> list[int]:
    sockets = [socket.socket() for _ in range(count)]
    try:
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def wait_until(label: str, predicate, timeout: float = 30):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except Exception as error:  # startup races are expected
            last_error = error
        time.sleep(0.1)
    raise AssertionError(f"Timed out waiting for {label}: {last_error}")


def stop(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(20)
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except (OSError, TimeoutError):
            pass


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def read_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise ConnectionError(f"Expected {size} bytes, received {len(result)}")
        result.extend(chunk)
    return bytes(result)


def process_usage(process: subprocess.Popen) -> tuple[float, int]:
    stat = Path(f"/proc/{process.pid}/stat").read_text().rsplit(") ", 1)[1].split()
    ticks = int(stat[11]) + int(stat[12])
    status = Path(f"/proc/{process.pid}/status").read_text().splitlines()
    peak_rss = next(int(line.split()[1]) for line in status if line.startswith("VmHWM:"))
    return ticks / os.sysconf("SC_CLK_TCK"), peak_rss


def percent(values: list[float], percentile: int) -> float:
    ordered = sorted(values)
    return round(ordered[max(0, min(len(ordered) - 1, (len(ordered) * percentile + 99) // 100 - 1))], 3)


def measure(name: str, count: int, concurrency: int, operation):
    began = time.monotonic()
    observations = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(operation, index) for index in range(count)]
        for future in as_completed(futures):
            try:
                observations.append(future.result())  # (round-trip seconds, echoed bytes)
            except Exception as error:
                observations.append((None, 0))
                print(f"{name}: {type(error).__name__}: {error}", file=sys.stderr)
    elapsed = time.monotonic() - began
    latency = [duration * 1000 for duration, _ in observations if duration is not None]
    delivered = sum(size for _, size in observations)
    result = {
        "attempts": count,
        "successes": len(latency),
        "losses": count - len(latency),
        "loss_rate": round((count - len(latency)) / count, 4),
        "concurrency": concurrency,
        "elapsed_s": round(elapsed, 3),
        "goodput_Bps": round(delivered / elapsed, 1),
        "operations_per_s": round(len(latency) / elapsed, 2),
    }
    if latency:
        result["latency_ms"] = {"mean": round(statistics.mean(latency), 3),
                                "p50": percent(latency, 50), "p95": percent(latency, 95),
                                "p99": percent(latency, 99), "max": round(max(latency), 3)}
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--linux-beacon", type=Path, required=True)
    parser.add_argument("--linux-module", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--thresholds", type=Path,
                        help="JSON limits per flow: max_p95_ms, min_goodput_Bps, max_loss_rate")
    parser.add_argument("--samples", type=int, default=4)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--payload-bytes", type=int, default=1024)
    parser.add_argument("--server-poll-ms", type=int, default=0,
                        help="TeamServer response polling interval in milliseconds")
    parser.add_argument("--beacon-sleep-seconds", type=float, default=0.0,
                        help="Sleep interval configured on both beacons")
    parser.add_argument("--log-level", choices=("warning", "info", "debug"), default="warning")
    args = parser.parse_args()
    if min(args.samples, args.concurrency, args.payload_bytes) < 1:
        parser.error("samples, concurrency, and payload-bytes must be positive")
    if args.server_poll_ms < 0 or not 0 <= args.beacon_sleep_seconds < float("inf"):
        parser.error("server-poll-ms and beacon-sleep-seconds must be nonnegative")

    import grpc

    with tempfile.TemporaryDirectory(prefix="c2-beacon-flow-") as temporary:
        root = Path(temporary)
        runtime = root / "runtime"
        shutil.copytree(args.runtime, runtime)
        beacon = runtime / "LinuxBeacons" / "x64" / "BeaconTcp"
        module = runtime / "LinuxModules" / "x64" / "libReversePortForward.so"
        beacon.parent.mkdir(parents=True, exist_ok=True)
        module.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.linux_beacon, beacon)
        shutil.copy2(args.linux_module, module)
        sys.path.insert(0, str(runtime / "Client"))
        from c2client_protocol import TeamServerApi_pb2 as pb
        from c2client_protocol import TeamServerApi_pb2_grpc as rpc

        grpc_port, listener_port, child_port, forward_port = reserve_ports(4)
        config_path = runtime / "TeamServer" / "TeamServerConfig.json"
        config = json.loads(config_path.read_text())
        config.update(ServerGRPCAdd="127.0.0.1", ServerGRPCPort=str(grpc_port),
                      JobDatabasePath=str(root / "jobs.sqlite"), LogLevel=args.log_level)
        config_path.write_text(json.dumps(config))
        credential = grpc.ssl_channel_credentials((runtime / "TeamServer" / "rootCA.crt").read_bytes())
        channel = grpc.secure_channel(f"127.0.0.1:{grpc_port}", credential,
                                      options=(("grpc.ssl_target_name_override", "localhost"),))
        stub = rpc.TeamServerApiStub(channel)
        processes: list[subprocess.Popen] = []
        log_paths = []

        def launch(command, cwd, name, env=None):
            log_path = root / f"{name}.log"
            log_paths.append(log_path)
            with log_path.open("wb") as output:
                process = subprocess.Popen(command, cwd=cwd, env=env, stdout=output,
                                           stderr=subprocess.STDOUT, start_new_session=True)
            processes.append(process)
            return process

        def auth_metadata():
            return (("authorization", f"Bearer {token}"), ("clientid", "beacon-flow-e2e"))

        def job(command, target, timeout=30):
            beacon_hash, listener_hash = target
            job_id = uuid.uuid4().hex
            request = pb.SubmitJobRequest(job_id=job_id, operation="session_command",
                input=json.dumps({"command": command, "beacon_hash": beacon_hash,
                                  "listener_hash": listener_hash}))
            started = time.monotonic()
            record = stub.SubmitJob(request, metadata=auth_metadata(), timeout=5)
            if record.state not in ("succeeded", "failed", "outcome_unknown"):
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError(f"Job {command} timed out ({job_id})")
                events = stub.SubscribeJobEvents(
                    pb.SubscribeJobEventsRequest(job_id=job_id, follow=True),
                    metadata=auth_metadata(), timeout=remaining)
                try:
                    for event in events:
                        if event.event_type in ("succeeded", "failed", "outcome_unknown"):
                            record = stub.GetJobExecution(pb.GetJobExecutionRequest(job_id=job_id),
                                                          metadata=auth_metadata(), timeout=5)
                            break
                finally:
                    events.cancel()
            if record.state not in ("succeeded", "failed", "outcome_unknown"):
                raise TimeoutError(f"Job {command} timed out ({job_id})")
            if record.state != "succeeded":
                raise AssertionError(f"Job {command} failed: {record.error_message}")
            return time.monotonic() - started, record

        def control_socks(action, target=""):
            record = stub.ControlSocks(pb.SocksControlRequest(job_id=uuid.uuid4().hex,
                action=action, beacon_hash=target), metadata=auth_metadata(), timeout=10)
            if record.state != "succeeded":
                raise AssertionError(f"SOCKS {action}: {record.state} {record.error_message}")

        def sessions():
            return list(stub.ListSessions(pb.Empty(), metadata=auth_metadata(), timeout=5))

        def listeners():
            return list(stub.ListListeners(pb.Empty(), metadata=auth_metadata(), timeout=5))

        def tunnel(port, payload, socks=False):
            started = time.monotonic()
            stage = "connect"
            with socket.create_connection(("127.0.0.1", 1080 if socks else port), timeout=20) as sock:
                sock.settimeout(20)
                try:
                    if socks:
                        stage = "SOCKS method"
                        sock.sendall(b"\x05\x01\x00")
                        if read_exact(sock, 2) != b"\x05\x00":
                            raise AssertionError("SOCKS method negotiation failed")
                        stage = "SOCKS CONNECT"
                        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + port.to_bytes(2, "big"))
                        response = read_exact(sock, 4)
                        if response[:2] != b"\x05\x00":
                            raise AssertionError(f"SOCKS CONNECT failed: {response.hex()}")
                        address_size = read_exact(sock, 1)[0] if response[3] == 3 else {1: 4, 4: 16}[response[3]]
                        read_exact(sock, address_size + 2)
                    stage = "echo"
                    sock.sendall(payload)
                    if read_exact(sock, len(payload)) != payload:
                        raise AssertionError("Echo mismatch")
                except TimeoutError as error:
                    raise TimeoutError(f"{stage} timed out") from error
            return time.monotonic() - started, len(payload)

        result = {"schema": 1, "scope": "loopback TeamServer → Linux BeaconTcp → child BeaconTcp",
                  "payload_bytes": args.payload_bytes,
                  "server_poll_ms": args.server_poll_ms,
                  "beacon_sleep_seconds": args.beacon_sleep_seconds,
                  "loss_definition": "application operations without an exact response before timeout"}
        echo_server = EchoServer(("127.0.0.1", 0), Echo)
        from threading import Thread
        echo_thread = Thread(target=echo_server.serve_forever, daemon=True)
        echo_thread.start()
        echo_port = echo_server.server_address[1]
        try:
            server_env = os.environ.copy()
            server_env["C2_RESPONSE_POLL_INTERVAL_MS"] = str(args.server_poll_ms)
            server = launch([str(runtime / "TeamServer" / "TeamServer"), "TeamServerConfig.json"],
                            runtime / "TeamServer", "teamserver", env=server_env)
            wait_until("TeamServer authentication", lambda: stub.Authenticate(
                pb.AuthRequest(username="admin", password="admin"), timeout=1).token
                if server.poll() is None else None)
            token = stub.Authenticate(pb.AuthRequest(username="admin", password="admin"), timeout=5).token
            ack = stub.AddListener(pb.Listener(type="tcp", ip="127.0.0.1", port=listener_port),
                                   metadata=auth_metadata(), timeout=5)
            assert ack.status == pb.OK and ack.listener_hash, ack
            primary = launch([str(beacon), "127.0.0.1", str(listener_port)], root, "primary")
            parent = wait_until("parent beacon", lambda: next(
                ((s.beacon_hash, s.listener_hash) for s in sessions()
                 if s.listener_hash == ack.listener_hash), None) if primary.poll() is None else None)
            sleep_command = f"sleep {args.beacon_sleep_seconds}"
            job(sleep_command, parent)
            job(f"listener start tcp 127.0.0.1 {child_port}", parent)
            child_listener = wait_until("child listener", lambda: next(
                (entry for entry in listeners() if entry.parent_listener_hash == ack.listener_hash
                 and entry.port == child_port), None))
            child_process = launch([str(beacon), "127.0.0.1", str(child_port)], root, "child")
            child = wait_until("child beacon", lambda: next(
                ((s.beacon_hash, s.listener_hash) for s in sessions()
                 if s.listener_hash == child_listener.listener_hash), None)
                if child_process.poll() is None else None)
            job(sleep_command, child)
            baseline_usage = [process_usage(process) for process in processes]
            result["child_jobs"] = measure("child_jobs", args.samples, args.concurrency,
                lambda _: (lambda response: (response[0], len(response[1].output_inline)))(job(sleep_command, child)))

            job("loadModule libReversePortForward.so", child)
            job(f"reversePortForward {forward_port} 127.0.0.1 {echo_port}", child)
            payload = bytes((index % 251 for index in range(args.payload_bytes)))
            result["reverse_port_forward"] = measure("reverse_port_forward", args.samples,
                args.concurrency, lambda _: tunnel(forward_port, payload))

            control_socks("start")
            control_socks("bind", child[0])
            result["socks5"] = measure("socks5", args.samples, args.concurrency,
                lambda _: tunnel(echo_port, payload, socks=True))
            control_socks("unbind")
            control_socks("stop")
            final_usage = [process_usage(process) for process in processes]
            result["process_usage"] = {
                name: {"cpu_s_during_flows": round(after[0] - before[0], 3),
                       "peak_rss_kib": after[1]}
                for name, before, after in zip(("teamserver", "parent_beacon", "child_beacon"),
                                               baseline_usage, final_usage)
            }
            print(json.dumps(result, indent=2))
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(result, indent=2) + "\n")
            limits = json.loads(args.thresholds.read_text()) if args.thresholds else {}
            for name in ("child_jobs", "reverse_port_forward", "socks5"):
                metric = result[name]
                flow_limits = limits.get(name, {})
                max_loss_rate = flow_limits.get("max_loss_rate", 0.0)
                if metric["loss_rate"] > max_loss_rate:
                    raise AssertionError(f"{name}: loss rate {metric['loss_rate']} > {max_loss_rate}")
                max_p95 = flow_limits.get("max_p95_ms")
                if max_p95 is not None and metric.get("latency_ms", {}).get("p95", float("inf")) > max_p95:
                    raise AssertionError(f"{name}: p95 latency exceeds {max_p95} ms")
                min_goodput = flow_limits.get("min_goodput_Bps")
                if min_goodput is not None and metric["goodput_Bps"] < min_goodput:
                    raise AssertionError(f"{name}: goodput below {min_goodput} B/s")
        except Exception:
            for path in log_paths:
                if path.exists():
                    print(f"--- {path.name} ---\n{path.read_text(errors='replace')[-5000:]}", file=sys.stderr)
            raise
        finally:
            for process in reversed(processes):
                stop(process)
            echo_server.shutdown()
            echo_server.server_close()
            echo_thread.join(timeout=2)
            channel.close()


if __name__ == "__main__":
    main()
