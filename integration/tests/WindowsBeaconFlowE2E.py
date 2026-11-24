"""End-to-end child beacon, RPF, and SOCKS measurements with Windows beacons.

The TeamServer and echo endpoint run on Linux. Both beacons run on a Windows VM
reachable over WinRM and a host-only network. C2_WINRM_PASSWORD is read only at
runtime so the credential never enters CMake cache files or CTest arguments.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from BeaconFlowE2E import Echo, EchoServer, measure, process_usage, read_exact, stop, wait_until


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def reserve_port(address: str) -> int:
    with socket.socket() as listener:
        listener.bind((address, 0))
        return listener.getsockname()[1]


class WindowsHost:
    def __init__(self, host: str, user: str, password: str):
        import winrm

        self.session = winrm.Session(
            f"http://{host}:5985/wsman", auth=(user, password), transport="ntlm",
            read_timeout_sec=40, operation_timeout_sec=30,
        )

    def run(self, script: str) -> str:
        result = self.session.run_ps("$ProgressPreference='SilentlyContinue'; " + script)
        output = result.std_out.decode("utf-8", errors="replace").strip()
        if result.status_code:
            error = result.std_err.decode("utf-8", errors="replace")
            raise RuntimeError(f"WinRM command failed ({result.status_code}): {error[-1000:]}")
        return output

    def reserve_port(self, address: str) -> int:
        return int(self.run(
            f"$listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse({ps_quote(address)}),0); "
            "$listener.Start(); $port=$listener.LocalEndpoint.Port; $listener.Stop(); $port"
        ).splitlines()[-1])

    def allow_inbound_port(self, port: int, remote_address: str) -> str:
        rule = f"C2-Windows-Beacon-Flow-{uuid.uuid4().hex}"
        self.run(
            f"New-NetFirewallRule -Name {ps_quote(rule)} -DisplayName {ps_quote(rule)} "
            f"-Direction Inbound -Action Allow -Protocol TCP -LocalPort {port} "
            f"-RemoteAddress {ps_quote(remote_address)} -ErrorAction Stop | Out-Null"
        )
        return rule

    def remove_firewall_rule(self, rule: str) -> None:
        self.run(f"Remove-NetFirewallRule -Name {ps_quote(rule)} -ErrorAction SilentlyContinue")

    def start_beacon(self, executable: str, address: str, port: int):
        command = subprocess.list2cmdline([executable, address, str(port)])
        output = self.run(
            f"if(-not (Test-Path -LiteralPath {ps_quote(executable)} -PathType Leaf))"
            "{throw 'Windows BeaconTcp executable is missing'}; "
            "$created=Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
            f"-Arguments @{{CommandLine={ps_quote(command)}}}; "
            "if($created.ReturnValue -ne 0){throw ('Win32_Process.Create: '+$created.ReturnValue)}; "
            "$created.ProcessId"
        )
        return WindowsProcess(self, int(output.splitlines()[-1]))


class WindowsProcess:
    def __init__(self, host: WindowsHost, pid: int):
        self.host = host
        self.pid = pid

    def poll(self):
        return None if self.host.run(
            f"if(Get-Process -Id {self.pid} -ErrorAction SilentlyContinue){{'alive'}}"
        ) == "alive" else 1

    def usage(self) -> tuple[float, int]:
        output = self.host.run(
            f"$p=Get-Process -Id {self.pid} -ErrorAction Stop; "
            "@{cpu=$p.CPU; peak=$p.PeakWorkingSet64} | ConvertTo-Json -Compress"
        )
        usage = json.loads(output)
        return float(usage["cpu"] or 0), int(usage["peak"] or 0) // 1024

    def stop(self) -> None:
        self.host.run(f"Stop-Process -Id {self.pid} -Force -ErrorAction SilentlyContinue")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--windows-module", type=Path, required=True)
    parser.add_argument("--windows-beacon", required=True, help="BeaconTcp.exe path on the VM")
    parser.add_argument("--windows-host", required=True, help="WinRM endpoint")
    parser.add_argument("--windows-user", required=True)
    parser.add_argument("--windows-ip", required=True, help="VM address for the child listener")
    parser.add_argument("--server-ip", required=True, help="Linux address reachable from the VM")
    parser.add_argument("--server-bind-ip", help="Linux bind address if server-ip is a NAT gateway")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--thresholds", type=Path)
    parser.add_argument("--samples", type=int, default=4)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--payload-bytes", type=int, default=1024)
    parser.add_argument("--server-poll-ms", type=int, default=0)
    parser.add_argument("--beacon-sleep-seconds", type=float, default=0.0)
    parser.add_argument("--log-level", choices=("warning", "info", "debug"), default="warning")
    args = parser.parse_args()
    if min(args.samples, args.concurrency, args.payload_bytes) < 1:
        parser.error("samples, concurrency, and payload-bytes must be positive")
    if args.server_poll_ms < 0 or not 0 <= args.beacon_sleep_seconds < float("inf"):
        parser.error("server-poll-ms and beacon-sleep-seconds must be nonnegative")
    password = os.environ.get("C2_WINRM_PASSWORD")
    if not password:
        parser.error("C2_WINRM_PASSWORD must be set for the Windows E2E test")
    if not args.windows_module.is_file():
        parser.error(f"Windows RPF module is missing: {args.windows_module}")

    import grpc
    from threading import Thread

    windows = WindowsHost(args.windows_host, args.windows_user, password)
    with tempfile.TemporaryDirectory(prefix="c2-windows-beacon-flow-") as temporary:
        root = Path(temporary)
        runtime = root / "runtime"
        shutil.copytree(args.runtime, runtime)
        module = runtime / "WindowsModules" / "x64" / "ReversePortForward.dll"
        module.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.windows_module, module)
        sys.path.insert(0, str(runtime / "Client"))
        from c2client_protocol import TeamServerApi_pb2 as pb
        from c2client_protocol import TeamServerApi_pb2_grpc as rpc

        grpc_port = reserve_port("127.0.0.1")
        server_bind_ip = args.server_bind_ip or args.server_ip
        listener_port = reserve_port(server_bind_ip)
        child_port = windows.reserve_port(args.windows_ip)
        forward_port = windows.reserve_port(args.windows_ip)
        while forward_port == child_port:
            forward_port = windows.reserve_port(args.windows_ip)
        config_path = runtime / "TeamServer" / "TeamServerConfig.json"
        config = json.loads(config_path.read_text())
        config.update(ServerGRPCAdd="127.0.0.1", ServerGRPCPort=str(grpc_port),
                      JobDatabasePath=str(root / "jobs.sqlite"), LogLevel=args.log_level)
        config_path.write_text(json.dumps(config))
        credential = grpc.ssl_channel_credentials((runtime / "TeamServer" / "rootCA.crt").read_bytes())
        channel = grpc.secure_channel(f"127.0.0.1:{grpc_port}", credential,
                                      options=(("grpc.ssl_target_name_override", "localhost"),))
        stub = rpc.TeamServerApiStub(channel)
        processes: list[subprocess.Popen | WindowsProcess] = []
        log_paths: list[Path] = []

        def launch_server():
            log_path = root / "teamserver.log"
            log_paths.append(log_path)
            with log_path.open("wb") as output:
                process = subprocess.Popen(
                    [str(runtime / "TeamServer" / "TeamServer"), "TeamServerConfig.json"],
                    cwd=runtime / "TeamServer", stdout=output, stderr=subprocess.STDOUT,
                    env={**os.environ, "C2_RESPONSE_POLL_INTERVAL_MS": str(args.server_poll_ms)},
                    start_new_session=True,
                )
            processes.append(process)
            return process

        def auth_metadata():
            return (("authorization", f"Bearer {token}"), ("clientid", "windows-beacon-flow-e2e"))

        def sessions():
            return list(stub.ListSessions(pb.Empty(), metadata=auth_metadata(), timeout=5))

        def listeners():
            return list(stub.ListListeners(pb.Empty(), metadata=auth_metadata(), timeout=5))

        def job(command: str, target: tuple[str, str], timeout: float = 30):
            beacon_hash, listener_hash = target
            job_id = uuid.uuid4().hex
            request = pb.SubmitJobRequest(
                job_id=job_id, operation="session_command",
                input=json.dumps({"command": command, "beacon_hash": beacon_hash,
                                  "listener_hash": listener_hash}),
            )
            started = time.monotonic()
            record = stub.SubmitJob(request, metadata=auth_metadata(), timeout=5)
            if record.state not in ("succeeded", "failed", "outcome_unknown"):
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError(f"Job {command} timed out ({job_id})")
                events = stub.SubscribeJobEvents(
                    pb.SubscribeJobEventsRequest(job_id=job_id, follow=True),
                    metadata=auth_metadata(), timeout=remaining,
                )
                try:
                    for event in events:
                        if event.event_type in ("succeeded", "failed", "outcome_unknown"):
                            record = stub.GetJobExecution(
                                pb.GetJobExecutionRequest(job_id=job_id),
                                metadata=auth_metadata(), timeout=5,
                            )
                            break
                finally:
                    events.cancel()
            if record.state != "succeeded":
                raise AssertionError(f"Job {command}: {record.state} {record.error_message}")
            return time.monotonic() - started, record

        def control_socks(action: str, target: str = ""):
            record = stub.ControlSocks(pb.SocksControlRequest(
                job_id=uuid.uuid4().hex, action=action, beacon_hash=target,
            ), metadata=auth_metadata(), timeout=10)
            if record.state != "succeeded":
                raise AssertionError(f"SOCKS {action}: {record.state} {record.error_message}")

        def tunnel(port: int, payload: bytes, socks: bool = False):
            started = time.monotonic()
            stage = "connect"
            with socket.create_connection(("127.0.0.1" if socks else args.windows_ip,
                                           1080 if socks else port), timeout=20) as sock:
                sock.settimeout(20)
                try:
                    if socks:
                        stage = "SOCKS method"
                        sock.sendall(b"\x05\x01\x00")
                        if read_exact(sock, 2) != b"\x05\x00":
                            raise AssertionError("SOCKS method negotiation failed")
                        stage = "SOCKS CONNECT"
                        sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(args.server_ip)
                                     + port.to_bytes(2, "big"))
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

        result = {"schema": 1, "scope": "TeamServer Linux → Windows BeaconTcp → Windows child BeaconTcp",
                  "payload_bytes": args.payload_bytes, "server_poll_ms": args.server_poll_ms,
                  "beacon_sleep_seconds": args.beacon_sleep_seconds,
                  "loss_definition": "application operations without an exact response before timeout"}
        echo_server = EchoServer((server_bind_ip, 0), Echo)
        echo_thread = Thread(target=echo_server.serve_forever, daemon=True)
        echo_thread.start()
        echo_port = echo_server.server_address[1]
        firewall_rule = None
        try:
            server = launch_server()
            wait_until("TeamServer authentication", lambda: stub.Authenticate(
                pb.AuthRequest(username="admin", password="admin"), timeout=1).token
                if server.poll() is None else None)
            token = stub.Authenticate(pb.AuthRequest(username="admin", password="admin"), timeout=5).token
            ack = stub.AddListener(pb.Listener(type="tcp", ip=server_bind_ip, port=listener_port),
                                   metadata=auth_metadata(), timeout=5)
            assert ack.status == pb.OK and ack.listener_hash, ack
            primary = windows.start_beacon(args.windows_beacon, args.server_ip, listener_port)
            processes.append(primary)
            parent = wait_until("parent beacon", lambda: next(
                ((s.beacon_hash, s.listener_hash) for s in sessions()
                 if s.listener_hash == ack.listener_hash), None) if primary.poll() is None else None)
            sleep_command = f"sleep {args.beacon_sleep_seconds}"
            job(sleep_command, parent)
            job(f"listener start tcp {args.windows_ip} {child_port}", parent)
            child_listener = wait_until("child listener", lambda: next(
                (entry for entry in listeners() if entry.parent_listener_hash == ack.listener_hash
                 and entry.port == child_port), None))
            child_process = windows.start_beacon(args.windows_beacon, args.windows_ip, child_port)
            processes.append(child_process)
            child = wait_until("child beacon", lambda: next(
                ((s.beacon_hash, s.listener_hash) for s in sessions()
                 if s.listener_hash == child_listener.listener_hash), None)
                if child_process.poll() is None else None)
            job(sleep_command, child)
            baseline = [process_usage(server), primary.usage(), child_process.usage()]
            result["child_jobs"] = measure("child_jobs", args.samples, args.concurrency,
                lambda _: (lambda response: (response[0], len(response[1].output_inline)))(job(sleep_command, child)))

            _, module_record = job("loadModule ReversePortForward.dll", child)
            if b"Success" not in module_record.output_inline:
                raise AssertionError(f"RPF module load: {module_record.output_inline!r}")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.connect((args.windows_host, 5985))
                linux_host_ip = probe.getsockname()[0]
            firewall_rule = windows.allow_inbound_port(forward_port, linux_host_ip)
            _, forward_record = job(f"reversePortForward {forward_port} 127.0.0.1 {echo_port}", child)
            if b"started" not in forward_record.output_inline:
                raise AssertionError(f"RPF start: {forward_record.output_inline!r}")
            payload = bytes((index % 251 for index in range(args.payload_bytes)))
            result["reverse_port_forward"] = measure("reverse_port_forward", args.samples,
                args.concurrency, lambda _: tunnel(forward_port, payload))

            control_socks("start")
            control_socks("bind", child[0])
            result["socks5"] = measure("socks5", args.samples, args.concurrency,
                lambda _: tunnel(echo_port, payload, socks=True))
            control_socks("unbind")
            control_socks("stop")
            after = [process_usage(server), primary.usage(), child_process.usage()]
            result["process_usage"] = {
                name: {"cpu_s_during_flows": round(end[0] - start[0], 3),
                       "peak_rss_kib": end[1]}
                for name, start, end in zip(("teamserver", "parent_beacon", "child_beacon"), baseline, after)
            }
            print(json.dumps(result, indent=2))
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(result, indent=2) + "\n")
            limits = json.loads(args.thresholds.read_text()) if args.thresholds else {}
            for name in ("child_jobs", "reverse_port_forward", "socks5"):
                metric = result[name]
                flow_limits = limits.get(name, {})
                if metric["loss_rate"] > flow_limits.get("max_loss_rate", 0.0):
                    raise AssertionError(f"{name}: unexpected operation loss")
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
            if firewall_rule:
                try:
                    windows.remove_firewall_rule(firewall_rule)
                except Exception as error:
                    print(f"Firewall cleanup failed: {error}", file=sys.stderr)
            for process in reversed(processes):
                try:
                    process.stop() if isinstance(process, WindowsProcess) else stop(process)
                except Exception as error:
                    print(f"Cleanup failed: {error}", file=sys.stderr)
            echo_server.shutdown()
            echo_server.server_close()
            echo_thread.join(timeout=2)
            channel.close()


if __name__ == "__main__":
    main()
