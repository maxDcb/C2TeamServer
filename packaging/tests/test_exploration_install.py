from __future__ import annotations

import argparse
import ctypes.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import exploration_install as installer  # noqa: E402


def _release(root: Path, marker: str) -> Path:
    server = root / "TeamServer"
    server.mkdir(parents=True)
    binary = server / "TeamServer"
    binary.write_text(f"#!/bin/sh\necho {marker}\n", encoding="utf-8")
    binary.chmod(0o755)
    (server / "TeamServerConfig.json").write_text(json.dumps({
        "ServerGRPCAdd": "0.0.0.0",
        "ServerGRPCPort": "50051",
        "ListenerHttpConfig": {},
        "ListenerHttpsConfig": {},
    }), encoding="utf-8")
    (server / "server.key").write_text("stale build key", encoding="utf-8")
    (server / "auth_credentials.json").write_text("stale build users", encoding="utf-8")
    (root / "TeamServerModules").mkdir()
    (root / "CommandSpecs").mkdir()
    return root


def _args(prefix: Path, bundle: Path) -> argparse.Namespace:
    return argparse.Namespace(
        prefix=prefix, bundle=bundle, version=None, client_only=False, server_only=True,
        hostname="localhost", tls_cert=None, tls_key=None, ca_cert=None,
        admin_password_file=None, uv=None,
    )


@pytest.mark.skipif(sys.platform != "linux" or not ctypes.util.find_library("argon2")
                    or not shutil.which("openssl"), reason="Linux TLS and Argon2 runtime required")
def test_server_install_and_update_preserve_state(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    first_release = _release(tmp_path / "first", "first")
    prefix = tmp_path / "home" / ".local" / "Exploration"
    installer.install(_args(prefix, first_release))
    first_output = capsys.readouterr().out
    assert "Initial admin password (shown once):" in first_output

    config_path = prefix / "server" / "config" / "TeamServerConfig.json"
    credentials_path = prefix / "server" / "config" / "auth_credentials.json"
    certificate_path = prefix / "server" / "config" / "tls" / "server.crt"
    config = json.loads(config_path.read_text())
    assert config["DataRoot"] == str(prefix / "server" / "data")
    assert config["AuthCredentialsFile"] == str(credentials_path)
    assert config["ServCrtFile"] == str(certificate_path)
    assert config["ServerGRPCAdd"] == "127.0.0.1"
    assert json.loads(credentials_path.read_text())["users"][0]["password_hash"].startswith("$argon2id$")
    assert credentials_path.stat().st_mode & 0o077 == 0
    assert not (prefix / "server" / "app" / "Release" / "TeamServer" / "server.key").exists()
    assert not (prefix / "server" / "app" / "Release" / "TeamServer" / "auth_credentials.json").exists()
    original_credentials = credentials_path.read_bytes()
    original_certificate = certificate_path.read_bytes()

    config["ServerGRPCPort"] = "55000"
    installer.private_json(config_path, config)
    database = prefix / "server" / "data" / "jobs.sqlite"
    database.write_bytes(b"persistent data")
    second_release = _release(tmp_path / "second", "second")
    installer.install(_args(prefix, second_release))
    assert "Initial admin password" not in capsys.readouterr().out
    assert json.loads(config_path.read_text())["ServerGRPCPort"] == "55000"
    assert credentials_path.read_bytes() == original_credentials
    assert certificate_path.read_bytes() == original_certificate
    assert database.read_bytes() == b"persistent data"
    assert "second" in (prefix / "server" / "app" / "Release" / "TeamServer" / "TeamServer").read_text()

    failed_release = _release(tmp_path / "failed", "failed")
    for name in ("pyproject.toml", "uv.lock", "C2Client/GUI.py",
                 "c2client_protocol/TeamServerApi_pb2.py"):
        target = failed_release / "Client" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("fixture", encoding="utf-8")
    all_args = _args(prefix, failed_release)
    all_args.server_only = False
    def fail_client(*_args):
        raise RuntimeError("client dependency installation failed")
    monkeypatch.setattr(installer, "install_client", fail_client)
    with pytest.raises(RuntimeError, match="client dependency installation failed"):
        installer.install(all_args)
    assert "second" in (prefix / "server" / "app" / "Release" / "TeamServer" / "TeamServer").read_text()
    assert not (prefix / "server" / "app.previous").exists()

    installer.reset_admin(prefix)
    assert "New admin password (shown once):" in capsys.readouterr().out
    assert credentials_path.read_bytes() != original_credentials
    assert json.loads(credentials_path.read_text())["users"][0]["password_hash"].startswith("$argon2id$")

    blocked_prefix = tmp_path / "blocked"
    (blocked_prefix / "server" / "app.previous").mkdir(parents=True)
    with pytest.raises(RuntimeError, match="Previous application backup still exists"):
        installer.install(_args(blocked_prefix, _release(tmp_path / "blocked-release", "blocked")))
    assert not (blocked_prefix / "server" / "config" / "auth_credentials.json").exists()


def test_extract_bundle_rejects_unsafe_paths(tmp_path: Path):
    archive = tmp_path / "bundle.tar.gz"
    payload = tmp_path / "payload"
    payload.write_text("bad", encoding="utf-8")
    with tarfile.open(archive, "w:gz") as output:
        output.add(payload, arcname="Release/../../outside")
    with pytest.raises(RuntimeError, match="unsafe path"):
        installer.extract_bundle(archive, tmp_path / "out")
    assert not (tmp_path / "outside").exists()


def test_extract_bundle_rejects_links_and_duplicates(tmp_path: Path):
    archive = tmp_path / "bundle.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        link = tarfile.TarInfo("Release/TeamServer/TeamServer")
        link.type = tarfile.SYMTYPE
        link.linkname = "/bin/sh"
        output.addfile(link)
    with pytest.raises(RuntimeError, match="link or unsupported entry"):
        installer.extract_bundle(archive, tmp_path / "links")

    payload = tmp_path / "payload"
    payload.write_text("duplicate", encoding="utf-8")
    with tarfile.open(archive, "w:gz") as output:
        output.add(payload, arcname="Release/duplicate")
        output.add(payload, arcname="Release/duplicate")
    with pytest.raises(RuntimeError, match="duplicate entries"):
        installer.extract_bundle(archive, tmp_path / "duplicates")


def test_release_checksum_detects_tampering(tmp_path: Path):
    import hashlib

    archive = tmp_path / "Release.tar.gz"
    checksum = tmp_path / "Release.tar.gz.sha256"
    archive.write_bytes(b"release archive")
    checksum.write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + "  Release.tar.gz\n")
    installer.verify_checksum(archive, checksum)
    archive.write_bytes(b"modified archive")
    with pytest.raises(RuntimeError, match="checksum mismatch"):
        installer.verify_checksum(archive, checksum)
    checksum.write_text("", encoding="ascii")
    with pytest.raises(RuntimeError, match="Invalid release checksum"):
        installer.verify_checksum(archive, checksum)


def test_client_update_restores_app_and_environment_when_sync_fails(
    tmp_path: Path, monkeypatch,
):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    prefix = tmp_path / "installed"
    trust = prefix / "client" / "config" / "trust.crt"
    trust.parent.mkdir(parents=True)
    trust.write_text("test certificate", encoding="utf-8")

    uv = tmp_path / "fake-uv"
    uv.write_text(
        "#!/usr/bin/env python3\n"
        "import os, pathlib, sys\n"
        "project = pathlib.Path(sys.argv[sys.argv.index('--project') + 1])\n"
        "environment = pathlib.Path(os.environ['UV_PROJECT_ENVIRONMENT'])\n"
        "environment.mkdir(parents=True)\n"
        "version = (project / 'version').read_text()\n"
        "(environment / 'version').write_text(version)\n"
        "sys.exit(7 if version == 'broken' else 0)\n",
        encoding="utf-8",
    )
    uv.chmod(0o755)

    def release(name: str) -> Path:
        root = tmp_path / name
        for relative in ("pyproject.toml", "uv.lock", "C2Client/GUI.py",
                         "c2client_protocol/TeamServerApi_pb2.py", "version"):
            target = root / "Client" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(name, encoding="utf-8")
        return root

    first = _args(prefix, release("first"))
    first.server_only = False
    first.client_only = True
    first.uv = uv
    installer.install(first)
    assert (prefix / "client" / ".venv" / "version").read_text() == "first"

    broken = _args(prefix, release("broken"))
    broken.server_only = False
    broken.client_only = True
    broken.uv = uv
    with pytest.raises(subprocess.CalledProcessError):
        installer.install(broken)

    assert (prefix / "client" / "app" / "version").read_text() == "first"
    assert (prefix / "client" / ".venv" / "version").read_text() == "first"
    assert not (prefix / "client" / "app.new").exists()
    assert not (prefix / "client" / ".venv.previous").exists()
