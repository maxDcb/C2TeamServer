"""Real TeamServer and Python client restart/resume test on a disk SQLite file."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import time


def reserve_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def client_environment(runtime: Path) -> dict[str, str]:
    environment = os.environ.copy()
    client_root = runtime / "Client"
    environment["PYTHONPATH"] = str(client_root) + os.pathsep + environment.get("PYTHONPATH", "")
    environment["C2_PROTOCOL_PYTHON_ROOT"] = str(client_root)
    environment["C2_CERT_PATH"] = str(runtime / "TeamServer" / "rootCA.crt")
    environment["C2_USERNAME"] = "admin"
    environment["C2_PASSWORD"] = "admin"
    environment["C2_GRPC_CONNECT_TIMEOUT_MS"] = "1000"
    return environment


def call_client(python: str, runtime: Path, port: int, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [python, "-m", "C2Client.jobs_cli", "--ip", "127.0.0.1", "--port", str(port), "--dev", *args],
        env=client_environment(runtime), capture_output=True, text=True, timeout=20,
    )


def checked_client(python: str, runtime: Path, port: int, *args: str) -> list[dict]:
    result = call_client(python, runtime, port, *args)
    if result.returncode:
        raise AssertionError(f"Client failed ({result.returncode}): {result.stderr}\n{result.stdout}")
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def start_server(runtime: Path, log: Path) -> subprocess.Popen:
    server_dir = runtime / "TeamServer"
    output = log.open("ab")
    try:
        return subprocess.Popen(
            [str(server_dir / "TeamServer"), "TeamServerConfig.json"],
            cwd=server_dir, stdout=output, stderr=subprocess.STDOUT,
        )
    finally:
        output.close()


def stop_server(server: subprocess.Popen) -> None:
    if server.poll() is None:
        server.send_signal(signal.SIGTERM)
        try:
            server.wait(timeout=8)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)


def wait_for_client(python: str, runtime: Path, port: int, server: subprocess.Popen) -> None:
    for _ in range(40):
        if server.poll() is not None:
            raise AssertionError(f"Server exited during startup: {server.returncode}")
        probe = call_client(python, runtime, port, "get", "missing-ready-probe")
        if "Job not found" in probe.stderr:
            return
        time.sleep(0.25)
    raise AssertionError("TeamServer did not become ready")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--client-python", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="c2-job-e2e-") as temp:
        root = Path(temp)
        runtime = root / "runtime"
        shutil.copytree(args.runtime, runtime)
        port = reserve_port()
        database = root / "jobs.sqlite"
        cursor_file = root / "cursor.txt"
        log = root / "server.log"
        config_path = runtime / "TeamServer" / "TeamServerConfig.json"
        config = json.loads(config_path.read_text())
        config["ServerGRPCAdd"] = "127.0.0.1"
        config["ServerGRPCPort"] = str(port)
        config["JobDatabasePath"] = str(database)
        config_path.write_text(json.dumps(config))
        server = None
        try:
            server = start_server(runtime, log)
            wait_for_client(args.client_python, runtime, port, server)
            first = checked_client(args.client_python, runtime, port,
                "submit", "echo", "persistent-result", "--job-id", "e2e-first")[0]
            assert first["state"] == "succeeded"
            assert base64.b64decode(first["output_base64"]) == b"persistent-result"
            repeated = checked_client(args.client_python, runtime, port,
                "submit", "echo", "persistent-result", "--job-id", "e2e-first")[0]
            assert repeated == first
            conflict = call_client(args.client_python, runtime, port,
                "submit", "echo", "changed", "--job-id", "e2e-first")
            assert conflict.returncode != 0 and "ALREADY_EXISTS" in conflict.stderr
            unknown = call_client(args.client_python, runtime, port,
                "submit", "unknown_operation", "x", "--job-id", "e2e-unknown")
            assert unknown.returncode != 0 and "INVALID_ARGUMENT" in unknown.stderr
            initial = checked_client(args.client_python, runtime, port,
                "watch", "--once", "--cursor-file", str(cursor_file))
            assert [event["event_type"] for event in initial] == ["accepted", "queued", "succeeded"]
            first_cursor = int(cursor_file.read_text())
            assert first_cursor == initial[-1]["event_id"]

            stop_server(server)
            server = start_server(runtime, log)
            wait_for_client(args.client_python, runtime, port, server)
            reopened = checked_client(args.client_python, runtime, port, "get", "e2e-first")[0]
            assert reopened == first
            assert checked_client(args.client_python, runtime, port,
                "watch", "--once", "--cursor-file", str(cursor_file)) == []
            second = checked_client(args.client_python, runtime, port,
                "submit", "echo", "after-restart", "--job-id", "e2e-second")[0]
            assert second["state"] == "succeeded"
            resumed = checked_client(args.client_python, runtime, port,
                "watch", "--once", "--cursor-file", str(cursor_file))
            assert [event["event_type"] for event in resumed] == ["accepted", "queued", "succeeded"]
            assert all(event["event_id"] > first_cursor for event in resumed)
            assert [event["event_id"] for event in resumed] == sorted(event["event_id"] for event in resumed)
            first_page = checked_client(args.client_python, runtime, port,
                "list", "--page-size", "1")[0]
            assert len(first_page["jobs"]) == 1
            second_page = checked_client(args.client_python, runtime, port,
                "list", "--page-size", "1",
                "--after-created-at", str(first_page["next_created_at"]),
                "--after-job-id", first_page["next_job_id"])[0]
            assert len(second_page["jobs"]) == 1
            assert {first_page["jobs"][0]["job_id"], second_page["jobs"][0]["job_id"]} == {
                "e2e-first", "e2e-second"}

            follow_cursor = int(cursor_file.read_text())
            watcher = subprocess.Popen(
                [args.client_python, "-m", "C2Client.jobs_cli", "--ip", "127.0.0.1",
                 "--port", str(port), "--dev", "watch", "--cursor-file", str(cursor_file),
                 "--max-events", "3"],
                env=client_environment(runtime), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
            )
            try:
                time.sleep(0.5)
                checked_client(args.client_python, runtime, port,
                    "submit", "echo", "followed", "--job-id", "e2e-third")
                output, errors = watcher.communicate(timeout=20)
                assert watcher.returncode == 0, errors
                followed = [json.loads(line) for line in output.splitlines() if line.strip()]
                assert [event["event_type"] for event in followed] == ["accepted", "queued", "succeeded"]
                assert all(event["event_id"] > follow_cursor for event in followed)
            finally:
                if watcher.poll() is None:
                    watcher.terminate()
                    watcher.wait(timeout=5)
        except Exception:
            if log.exists():
                print(log.read_text(errors="replace")[-6000:])
            raise
        finally:
            if server is not None:
                stop_server(server)


if __name__ == "__main__":
    main()
