"""Exercise a real installed TeamServer with generated TLS and Argon2id credentials."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile

import grpc


def reserve_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-root", type=Path, required=True)
    parser.add_argument("--installer", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.release_root / "Client"))
    from c2client_protocol import TeamServerApi_pb2, TeamServerApi_pb2_grpc

    with tempfile.TemporaryDirectory(prefix="exploration-installed-e2e-") as directory:
        prefix = Path(directory) / "Exploration"
        result = subprocess.run(
            [sys.executable, str(args.installer), "install", "--server-only",
             "--bundle", str(args.release_root), "--prefix", str(prefix)],
            check=True, capture_output=True, text=True, timeout=30,
            env={**os.environ, "HOME": directory},
        )
        match = re.search(r"Initial admin password \(shown once\): (\S+)", result.stdout)
        assert match, result.stdout
        password = match.group(1)
        credentials = json.loads((prefix / "server" / "config" / "auth_credentials.json").read_text())
        assert credentials["users"][0]["password_hash"].startswith("$argon2id$")
        assert password not in (prefix / "server" / "config" / "auth_credentials.json").read_text()

        config_path = prefix / "server" / "config" / "TeamServerConfig.json"
        config = json.loads(config_path.read_text())
        port = reserve_port()
        config["ServerGRPCPort"] = str(port)
        config_path.write_text(json.dumps(config))
        manager = prefix / "bin" / "exploration"
        try:
            subprocess.run([sys.executable, str(manager), "server", "start", "--prefix", str(prefix)],
                           check=True, capture_output=True, text=True, timeout=10)
            certificate = (prefix / "server" / "config" / "tls" / "trust.crt").read_bytes()
            channel = grpc.secure_channel(
                f"127.0.0.1:{port}", grpc.ssl_channel_credentials(certificate))
            grpc.channel_ready_future(channel).result(timeout=10)
            stub = TeamServerApi_pb2_grpc.TeamServerApiStub(channel)
            wrong = stub.Authenticate(TeamServerApi_pb2.AuthRequest(username="admin", password="wrong"))
            assert wrong.status == TeamServerApi_pb2.KO
            valid = stub.Authenticate(TeamServerApi_pb2.AuthRequest(username="admin", password=password))
            assert valid.status == TeamServerApi_pb2.OK
            assert valid.token
            listeners = list(stub.ListListeners(TeamServerApi_pb2.Empty(),
                                                metadata=(("authorization", f"Bearer {valid.token}"),)))
            assert listeners == []
        finally:
            subprocess.run([sys.executable, str(manager), "server", "stop", "--prefix", str(prefix)],
                           capture_output=True, text=True, timeout=15)

        account_file = prefix / "server" / "config" / "auth_credentials.json"
        account_file.rename(account_file.with_suffix(".disabled"))
        blocked = subprocess.run([sys.executable, str(manager), "server", "run", "--prefix", str(prefix)],
                                 capture_output=True, text=True, timeout=10)
        assert blocked.returncode != 0
        assert "Authentication credential file not found" in blocked.stderr


if __name__ == "__main__":
    main()
