#!/usr/bin/env python3
"""Linux/WSL installer and local launcher for Exploration releases."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request


REPOSITORY = "maxDcb/C2TeamServer"
UV_VERSION = "0.13.5"
DEFAULT_PREFIX = Path.home() / ".local" / "Exploration"
ARCHIVE_NAME = "Release.tar.gz"


def fail(message: str) -> None:
    raise RuntimeError(message)


def private_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    path.chmod(0o600)


def copy_private(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o600)


def password_hash(password: str) -> str:
    library_name = ctypes.util.find_library("argon2")
    if not library_name:
        fail("libargon2 is required (install the libargon2-1 system package).")
    library = ctypes.CDLL(library_name)
    function = library.argon2id_hash_encoded
    function.argtypes = [
        ctypes.c_uint, ctypes.c_uint, ctypes.c_uint,
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
    ]
    function.restype = ctypes.c_int
    password_bytes = password.encode("utf-8")
    salt = secrets.token_bytes(16)
    encoded = ctypes.create_string_buffer(256)
    result = function(2, 19456, 1, password_bytes, len(password_bytes),
                      salt, len(salt), 32, encoded, len(encoded))
    if result != 0:
        fail(f"Argon2id password hashing failed: {result}")
    return encoded.value.decode("ascii")


def create_credentials(path: Path, password_file: Path | None) -> str | None:
    if path.exists():
        return None
    if password_file:
        password = password_file.read_text(encoding="utf-8").rstrip("\r\n")
        if not password:
            fail("The admin password file is empty.")
    else:
        password = secrets.token_urlsafe(32)
    private_json(path, {
        "token_ttl_minutes": 60,
        "users": [{"username": "admin", "password_hash": password_hash(password)}],
    })
    return password if not password_file else None


def subject_alternative_name(hostname: str) -> str:
    names = ["DNS:localhost", "IP:127.0.0.1"]
    if hostname not in ("localhost", "127.0.0.1"):
        try:
            ipaddress.ip_address(hostname)
            names.append(f"IP:{hostname}")
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", hostname):
                fail("Invalid TLS hostname.")
            names.append(f"DNS:{hostname}")
    return ",".join(names)


def create_tls(directory: Path, hostname: str, cert: Path | None, key: Path | None,
               trust: Path | None) -> None:
    certificate = directory / "server.crt"
    private_key = directory / "server.key"
    trust_certificate = directory / "trust.crt"
    listener_certificate = directory / "listener.crt"
    listener_key = directory / "listener.key"
    if certificate.exists() and private_key.exists() and trust_certificate.exists():
        return
    if any(path.exists() for path in (certificate, private_key, trust_certificate)):
        fail("Incomplete TLS configuration; restore the missing files before updating.")
    directory.mkdir(parents=True, exist_ok=True)
    if cert or key or trust:
        if not cert or not key:
            fail("--tls-cert and --tls-key must be provided together.")
        shutil.copyfile(cert, certificate)
        copy_private(key, private_key)
        shutil.copyfile(trust or cert, trust_certificate)
    else:
        if not shutil.which("openssl"):
            fail("OpenSSL is required to create the server certificate.")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256",
            "-days", "825", "-nodes", "-keyout", str(private_key),
            "-out", str(certificate), "-subj", f"/CN={hostname}",
            "-addext", f"subjectAltName={subject_alternative_name(hostname)}",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.copyfile(certificate, trust_certificate)
        private_key.chmod(0o600)
    shutil.copyfile(certificate, listener_certificate)
    copy_private(private_key, listener_key)
    certificate.chmod(0o644)
    trust_certificate.chmod(0o644)
    listener_certificate.chmod(0o644)


def server_config(template: Path, prefix: Path, hostname: str) -> dict:
    config = json.loads(template.read_text(encoding="utf-8"))
    server = prefix / "server"
    app = server / "app" / "Release"
    data = server / "data"
    tls = server / "config" / "tls"
    paths = {
        "ReleaseRoot": app,
        "DataRoot": data,
        "TeamServerModulesDirectoryPath": app / "TeamServerModules",
        "LinuxModulesDirectoryPath": app / "LinuxModules",
        "WindowsModulesDirectoryPath": app / "WindowsModules",
        "LinuxBeaconsDirectoryPath": app / "LinuxBeacons",
        "WindowsBeaconsDirectoryPath": app / "WindowsBeacons",
        "CommandSpecsDirectoryPath": app / "CommandSpecs",
        "ToolsDirectoryPath": data / "Tools",
        "ScriptsDirectoryPath": data / "Scripts",
        "UploadedArtifactsDirectoryPath": data / "UploadedArtifacts",
        "GeneratedArtifactsDirectoryPath": data / "GeneratedArtifacts",
        "HostedArtifactsDirectoryPath": data / "GeneratedArtifacts" / "hosted",
        "CredentialVaultDirectoryPath": data / "CredentialVault",
        "CredentialVaultPath": data / "CredentialVault" / "vault.json",
        "CredentialVaultKeyFile": data / "CredentialVault" / "vault.key",
        "JobDatabasePath": data / "jobs.sqlite",
        "ServCrtFile": tls / "server.crt",
        "ServKeyFile": tls / "server.key",
        "RootCA": tls / "trust.crt",
        "AuthCredentialsFile": server / "config" / "auth_credentials.json",
    }
    config.update({key: str(value) for key, value in paths.items()})
    config["ServerGRPCAdd"] = "127.0.0.1" if hostname in ("localhost", "127.0.0.1") else "0.0.0.0"
    if hostname not in ("localhost", "127.0.0.1"):
        try:
            ipaddress.ip_address(hostname)
            config["ExposedIp"] = hostname
        except ValueError:
            config["DomainName"] = hostname
    for section in ("ListenerHttpConfig", "ListenerHttpsConfig"):
        config.setdefault(section, {})["downloadFolder"] = str(data / "GeneratedArtifacts" / "hosted")
    config["ListenerHttpsConfig"]["ServHttpsListenerCrtFile"] = str(tls / "listener.crt")
    config["ListenerHttpsConfig"]["ServHttpsListenerKeyFile"] = str(tls / "listener.key")
    return config


def _download(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "Exploration-installer"})
    with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as output:
        shutil.copyfileobj(response, output)


def download_bundle(directory: Path, version: str | None) -> Path:
    if version and not re.fullmatch(r"[A-Za-z0-9._-]+", version):
        fail("Invalid release version.")
    if version:
        base = f"https://github.com/{REPOSITORY}/releases/download/{version}"
    else:
        api = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
        request = urllib.request.Request(api, headers={"User-Agent": "Exploration-installer"})
        with urllib.request.urlopen(request, timeout=30) as response:
            release = json.load(response)
        assets = {asset["name"]: asset["browser_download_url"] for asset in release["assets"]}
        if ARCHIVE_NAME not in assets or ARCHIVE_NAME + ".sha256" not in assets:
            fail("The latest release has no installable archive and checksum.")
        archive = directory / ARCHIVE_NAME
        checksum = directory / (ARCHIVE_NAME + ".sha256")
        _download(assets[ARCHIVE_NAME], archive)
        _download(assets[ARCHIVE_NAME + ".sha256"], checksum)
        verify_checksum(archive, checksum)
        return archive
    archive = directory / ARCHIVE_NAME
    checksum = directory / (ARCHIVE_NAME + ".sha256")
    _download(base + "/" + ARCHIVE_NAME, archive)
    _download(base + "/" + ARCHIVE_NAME + ".sha256", checksum)
    verify_checksum(archive, checksum)
    return archive


def verify_checksum(archive: Path, checksum: Path) -> None:
    fields = checksum.read_text(encoding="ascii").split()
    expected = fields[0].lower() if fields else ""
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        fail("Invalid release checksum.")
    hasher = hashlib.sha256()
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    if digest != expected:
        fail("Release archive checksum mismatch.")


def extract_bundle(archive: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    total_size = 0
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            parts = Path(member.name).parts
            if not parts or parts[0] != "Release" or ".." in parts or member.name.startswith("/"):
                fail("Release archive contains an unsafe path.")
            if not member.isfile() and not member.isdir():
                fail("Release archive contains a link or unsupported entry.")
            normalized_name = Path(*parts).as_posix()
            if normalized_name in seen:
                fail("Release archive contains duplicate entries.")
            seen.add(normalized_name)
            total_size += member.size
            if total_size > 8 * 1024**3:
                fail("Release archive exceeds the size limit.")
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as stream, target.open("wb") as output:
                    shutil.copyfileobj(stream, output)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
    return destination / "Release"


def release_root(bundle: Path | None, version: str | None, temporary: Path) -> Path:
    if bundle is None:
        return extract_bundle(download_bundle(temporary, version), temporary / "extracted")
    bundle = bundle.expanduser().resolve()
    if bundle.is_file():
        return extract_bundle(bundle, temporary / "extracted")
    root = bundle / "Release" if (bundle / "Release").is_dir() else bundle
    if not root.is_dir():
        fail(f"Release bundle not found: {bundle}")
    return root


def validate_release(root: Path, server: bool, client: bool) -> None:
    if server:
        for name in ("TeamServer/TeamServer", "TeamServer/TeamServerConfig.json",
                     "TeamServerModules", "CommandSpecs"):
            if not (root / name).exists():
                fail(f"Release is missing {name}.")
    if client:
        for name in ("Client/pyproject.toml", "Client/uv.lock", "Client/C2Client/GUI.py",
                     "Client/c2client_protocol/TeamServerApi_pb2.py"):
            if not (root / name).is_file():
                fail(f"Release is missing {name}.")


def swap_directory(source: Path, destination: Path) -> None:
    backup = destination.with_name(destination.name + ".previous")
    if backup.exists():
        fail(f"Previous application backup still exists: {backup}")
    if destination.exists():
        destination.rename(backup)
    try:
        source.rename(destination)
    except Exception:
        if backup.exists():
            backup.rename(destination)
        raise


def restore_directory(destination: Path, existed_before: bool) -> None:
    backup = destination.with_name(destination.name + ".previous")
    if backup.exists():
        if destination.exists():
            shutil.rmtree(destination)
        backup.rename(destination)
    elif not existed_before and destination.exists():
        shutil.rmtree(destination)


def finalize_directory(destination: Path) -> None:
    backup = destination.with_name(destination.name + ".previous")
    if backup.exists():
        shutil.rmtree(backup)


def install_server(root: Path, prefix: Path, args: argparse.Namespace) -> str | None:
    server = prefix / "server"
    staged = server / "app.new"
    if staged.exists():
        shutil.rmtree(staged)
    release = staged / "Release"
    release.mkdir(parents=True)
    for name in ("TeamServer", "TeamServerModules", "CommandSpecs",
                 "LinuxBeacons", "LinuxModules", "WindowsBeacons", "WindowsModules"):
        source = root / name
        if source.is_dir():
            shutil.copytree(source, release / name)
    for name in ("auth_credentials.json", "server.key", "server.crt", "rootCA.crt",
                 "localhost.key", "localhost.crt", "TeamServerConfig.json"):
        (release / "TeamServer" / name).unlink(missing_ok=True)
    logs = server / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    bundled_logs = release / "TeamServer" / "logs"
    if bundled_logs.exists():
        shutil.rmtree(bundled_logs)
    bundled_logs.symlink_to(logs, target_is_directory=True)
    config_dir = server / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    (server / "data").mkdir(parents=True, exist_ok=True)
    create_tls(config_dir / "tls", args.hostname, args.tls_cert, args.tls_key, args.ca_cert)
    config_file = config_dir / "TeamServerConfig.json"
    if not config_file.exists():
        private_json(config_file, server_config(root / "TeamServer" / "TeamServerConfig.json",
                                               prefix, args.hostname))
    swap_directory(staged, server / "app")
    return create_credentials(config_dir / "auth_credentials.json", args.admin_password_file)


def ensure_uv(prefix: Path, override: Path | None) -> Path:
    if override:
        if not override.is_file():
            fail(f"uv executable not found: {override}")
        return override
    existing = shutil.which("uv")
    if existing:
        return Path(existing)
    binary = prefix / "tools" / "uv" / "uv"
    if binary.is_file():
        return binary
    destination = binary.parent
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="exploration-uv-") as directory:
        script = Path(directory) / "install.sh"
        _download(f"https://astral.sh/uv/{UV_VERSION}/install.sh", script)
        environment = os.environ.copy()
        environment["UV_INSTALL_DIR"] = str(destination)
        environment["UV_NO_MODIFY_PATH"] = "1"
        subprocess.run(["sh", str(script)], check=True, env=environment)
    if not binary.is_file():
        fail("uv installation did not produce an executable.")
    return binary


def install_client(root: Path, prefix: Path, args: argparse.Namespace) -> None:
    client = prefix / "client"
    staged = client / "app.new"
    if staged.exists():
        shutil.rmtree(staged)
    shutil.copytree(root / "Client", staged)
    config_dir = client / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    (client / "data").mkdir(parents=True, exist_ok=True)
    trust = config_dir / "trust.crt"
    if not trust.exists():
        source = args.ca_cert or prefix / "server" / "config" / "tls" / "trust.crt"
        if not source.is_file():
            fail("Client-only installation requires --ca-cert for the TeamServer.")
        shutil.copyfile(source, trust)
        trust.chmod(0o644)
    env_file = config_dir / "client.env"
    if not env_file.exists():
        env_file.write_text(
            f"C2_IP={args.hostname if args.hostname != 'localhost' else '127.0.0.1'}\n"
            "C2_PORT=50051\n"
            f"C2_CERT_PATH={trust}\n"
            f"C2_LOG_DIR={client / 'data' / 'logs'}\n"
            "C2_USERNAME=admin\n", encoding="utf-8")
        env_file.chmod(0o600)
    uv = ensure_uv(prefix, args.uv)
    environment_path = client / ".venv"
    environment_backup = client / ".venv.previous"
    if environment_backup.exists():
        fail(f"Previous application backup still exists: {environment_backup}")
    if environment_path.exists():
        environment_path.rename(environment_backup)
    environment = os.environ.copy()
    environment["UV_PROJECT_ENVIRONMENT"] = str(environment_path)
    subprocess.run([str(uv), "sync", "--project", str(staged), "--locked", "--no-dev",
                    "--no-editable", "--python", "3.12"], check=True, env=environment)
    swap_directory(staged, client / "app")


def install(args: argparse.Namespace) -> None:
    prefix = args.prefix.expanduser().resolve()
    if not sys.platform.startswith("linux"):
        fail("The installer currently supports Linux and WSL.")
    if os.geteuid() == 0:
        fail("Run the installer as a regular user, without sudo.")
    components = (not args.client_only, not args.server_only)
    if args.client_only:
        components = (False, True)
    elif args.server_only:
        components = (True, False)
    server_selected, client_selected = components
    if server_selected and not ctypes.util.find_library("sqlite3"):
        fail("SQLite runtime is required (install the libsqlite3-0 system package).")
    prefix.mkdir(parents=True, exist_ok=True)
    prefix.chmod(0o700)
    with tempfile.TemporaryDirectory(prefix="exploration-release-") as directory:
        root = release_root(args.bundle, args.version, Path(directory))
        validate_release(root, server_selected, client_selected)
        server_app = prefix / "server" / "app"
        client_app = prefix / "client" / "app"
        client_environment = prefix / "client" / ".venv"
        server_existed = server_app.exists()
        client_existed = client_app.exists()
        client_environment_existed = client_environment.exists()
        was_running = server_running(prefix) if server_selected else False
        client_was_running = client_pid(prefix) is not None if client_selected else False
        password = None
        try:
            if client_was_running:
                stop_client(prefix)
            if was_running:
                stop_server(prefix)
            password = install_server(root, prefix, args) if server_selected else None
            if client_selected:
                install_client(root, prefix, args)
            bin_dir = prefix / "bin"
            bin_dir.mkdir(parents=True, exist_ok=True)
            manager = bin_dir / "exploration"
            if Path(__file__).resolve() != manager.resolve():
                shutil.copyfile(Path(__file__), manager)
            manager.chmod(0o755)
            user_bin = Path.home() / ".local" / "bin"
            user_bin.mkdir(parents=True, exist_ok=True)
            link = user_bin / "exploration"
            if not link.exists() and not link.is_symlink():
                link.symlink_to(manager)
            if was_running:
                start_server(prefix)
            if client_was_running:
                start_client(prefix)
            private_json(prefix / "install.json", {
                "version": args.version or "latest",
                "server": (prefix / "server" / "app").exists(),
                "client": (prefix / "client" / "app").exists(),
            })
            if server_selected:
                finalize_directory(server_app)
            if client_selected:
                finalize_directory(client_app)
                finalize_directory(client_environment)
        except Exception:
            if password:
                print(f"Initial admin password (shown once): {password}")
            if was_running and server_running(prefix):
                stop_server(prefix)
            if client_was_running and client_pid(prefix) is not None:
                stop_client(prefix)
            if server_selected:
                restore_directory(server_app, server_existed)
            if client_selected:
                restore_directory(client_app, client_existed)
                restore_directory(client_environment, client_environment_existed)
                shutil.rmtree(prefix / "client" / "app.new", ignore_errors=True)
            if was_running and not server_running(prefix):
                start_server(prefix)
            if client_was_running and client_pid(prefix) is None:
                start_client(prefix)
            raise
    print(f"Exploration installed in {prefix}")
    if password:
        print(f"Initial admin password (shown once): {password}")
    if str(user_bin) not in os.environ.get("PATH", "").split(os.pathsep):
        print(f"Add {user_bin} to PATH, or use {bin_dir / 'exploration'}")


def server_paths(prefix: Path) -> tuple[Path, Path, Path]:
    server = prefix / "server"
    return (server / "app" / "Release" / "TeamServer" / "TeamServer",
            server / "config" / "TeamServerConfig.json",
            server / "data" / "server.pid")


def server_pid(prefix: Path) -> int | None:
    binary, config, pid_file = server_paths(prefix)
    if not pid_file.is_file():
        return None
    try:
        pid = int(pid_file.read_text(encoding="ascii").strip())
        command_line = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        if str(binary).encode() in command_line and str(config).encode() in command_line:
            return pid
    except (OSError, ValueError):
        pass
    pid_file.unlink(missing_ok=True)
    return None


def server_running(prefix: Path) -> bool:
    return server_pid(prefix) is not None


def start_server(prefix: Path) -> None:
    binary, config, pid_file = server_paths(prefix)
    if server_running(prefix):
        fail("TeamServer is already running.")
    if not binary.is_file() or not config.is_file():
        fail("TeamServer is not installed.")
    log_path = prefix / "server" / "logs" / "console.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("ab") as output:
        process = subprocess.Popen([str(binary), str(config)], cwd=binary.parent,
                                   stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True)
    time.sleep(0.2)
    if process.poll() is not None:
        fail(f"TeamServer exited during startup. Read {log_path}")
    pid_file.write_text(str(process.pid) + "\n", encoding="ascii")
    print(f"TeamServer started (PID {process.pid}).")


def stop_server(prefix: Path) -> None:
    pid = server_pid(prefix)
    if pid is None:
        print("TeamServer is stopped.")
        return
    os.kill(pid, signal.SIGTERM)
    for _ in range(100):
        if server_pid(prefix) is None:
            print("TeamServer stopped.")
            return
        time.sleep(0.1)
    fail("TeamServer did not stop within 10 seconds.")


def launch_client(prefix: Path, arguments: list[str]) -> None:
    client = prefix / "client"
    python = client / ".venv" / "bin" / "python"
    if not python.is_file():
        fail("Client is not installed.")
    environment = os.environ.copy()
    environment["C2_ENV_FILE"] = str(client / "config" / "client.env")
    environment["C2_PROTOCOL_PYTHON_ROOT"] = str(client / "app")
    environment["PYTHONPATH"] = str(client / "app") + os.pathsep + environment.get("PYTHONPATH", "")
    (client / "data" / "logs").mkdir(parents=True, exist_ok=True)
    os.chdir(client / "data")
    (client / "data" / "client.pid").write_text(str(os.getpid()) + "\n", encoding="ascii")
    os.execve(str(python), [str(python), "-m", "C2Client.GUI", *arguments], environment)


def client_pid(prefix: Path) -> int | None:
    client = prefix / "client"
    pid_file = client / "data" / "client.pid"
    if not pid_file.is_file():
        return None
    try:
        pid = int(pid_file.read_text(encoding="ascii").strip())
        command_line = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        if b"C2Client.GUI" in command_line and str(client / ".venv" / "bin" / "python").encode() in command_line:
            return pid
    except (OSError, ValueError):
        pass
    pid_file.unlink(missing_ok=True)
    return None


def start_client(prefix: Path) -> None:
    if client_pid(prefix) is not None:
        fail("Client is already running.")
    client = prefix / "client"
    if not (client / ".venv" / "bin" / "python").is_file():
        fail("Client is not installed.")
    log_path = client / "data" / "logs" / "console.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("ab") as output:
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "client",
                                    "--prefix", str(prefix), "run"],
                                   stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True)
    time.sleep(0.2)
    if process.poll() is not None:
        fail(f"Client exited during startup. Read {log_path}")
    print(f"Client started (PID {process.pid}).")


def stop_client(prefix: Path) -> None:
    pid = client_pid(prefix)
    if pid is None:
        print("Client is stopped.")
        return
    os.kill(pid, signal.SIGTERM)
    for _ in range(100):
        if client_pid(prefix) is None:
            print("Client stopped.")
            return
        time.sleep(0.1)
    fail("Client did not stop within 10 seconds.")


def reset_admin(prefix: Path) -> None:
    path = prefix / "server" / "config" / "auth_credentials.json"
    if not path.is_file():
        fail("TeamServer credentials are not installed.")
    credentials = json.loads(path.read_text(encoding="utf-8"))
    users = credentials.get("users")
    if not isinstance(users, list):
        fail("The credentials file has an unsupported format.")
    password = secrets.token_urlsafe(32)
    entry = next((user for user in users if user.get("username") == "admin"), None)
    if entry is None:
        entry = {"username": "admin"}
        users.append(entry)
    entry["password_hash"] = password_hash(password)
    entry.pop("password", None)
    was_running = server_running(prefix)
    if was_running:
        stop_server(prefix)
    private_json(path, credentials)
    print(f"New admin password (shown once): {password}")
    if was_running:
        start_server(prefix)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install and control Exploration on Linux/WSL.")
    commands = parser.add_subparsers(dest="command", required=True)
    install_parser = commands.add_parser("install")
    install_parser.add_argument("--prefix", type=Path, default=DEFAULT_PREFIX)
    install_parser.add_argument("--bundle", type=Path)
    install_parser.add_argument("--version")
    selection = install_parser.add_mutually_exclusive_group()
    selection.add_argument("--client-only", action="store_true")
    selection.add_argument("--server-only", action="store_true")
    install_parser.add_argument("--hostname", default="localhost")
    install_parser.add_argument("--tls-cert", type=Path)
    install_parser.add_argument("--tls-key", type=Path)
    install_parser.add_argument("--ca-cert", type=Path)
    install_parser.add_argument("--admin-password-file", type=Path)
    install_parser.add_argument("--uv", type=Path, help=argparse.SUPPRESS)
    server_parser = commands.add_parser("server")
    server_parser.add_argument("action", choices=("run", "start", "stop", "status", "logs", "reset-admin"))
    server_parser.add_argument("--prefix", type=Path)
    server_parser.add_argument("--follow", action="store_true")
    client_parser = commands.add_parser("client")
    client_parser.add_argument("--prefix", type=Path)
    client_parser.add_argument("action", nargs="?", default="run",
                               choices=("run", "start", "stop", "status", "logs"))
    client_parser.add_argument("arguments", nargs=argparse.REMAINDER)
    update_parser = commands.add_parser("update")
    update_parser.add_argument("--prefix", type=Path)
    update_parser.add_argument("--bundle", type=Path)
    update_parser.add_argument("--version")
    args = parser.parse_args(argv)
    if args.command == "install":
        install(args)
        return 0
    prefix = (args.prefix or Path(__file__).resolve().parents[1]).expanduser().resolve()
    if args.command == "update":
        metadata = json.loads((prefix / "install.json").read_text(encoding="utf-8"))
        install_args = argparse.Namespace(
            prefix=prefix, bundle=args.bundle, version=args.version,
            client_only=metadata["client"] and not metadata["server"],
            server_only=metadata["server"] and not metadata["client"],
            hostname="localhost", tls_cert=None, tls_key=None, ca_cert=None,
            admin_password_file=None, uv=None,
        )
        install(install_args)
        return 0
    if args.command == "client":
        if args.action == "run":
            launch_client(prefix, args.arguments)
        elif args.action == "start":
            start_client(prefix)
        elif args.action == "stop":
            stop_client(prefix)
        elif args.action == "status":
            pid = client_pid(prefix)
            print(f"Client running (PID {pid})." if pid else "Client stopped.")
        elif args.action == "logs":
            path = prefix / "client" / "data" / "logs" / "console.log"
            if not path.exists():
                fail("No client log is available yet.")
            subprocess.run(["tail", "-n", "100", str(path)], check=True)
        return 0
    if args.action == "run":
        binary, config, pid_file = server_paths(prefix)
        if not binary.is_file() or not config.is_file():
            fail("TeamServer is not installed.")
        if server_running(prefix):
            fail("TeamServer is already running.")
        pid_file.write_text(str(os.getpid()) + "\n", encoding="ascii")
        os.chdir(binary.parent)
        os.execv(str(binary), [str(binary), str(config)])
    elif args.action == "start":
        start_server(prefix)
    elif args.action == "stop":
        stop_server(prefix)
    elif args.action == "status":
        print(f"TeamServer running (PID {server_pid(prefix)})." if server_running(prefix)
              else "TeamServer stopped.")
    elif args.action == "logs":
        path = prefix / "server" / "logs" / "TeamServer.txt"
        if not path.exists():
            path = prefix / "server" / "logs" / "console.log"
        if not path.exists():
            fail("No TeamServer log is available yet.")
        subprocess.run(["tail", "-n", "100", *(['-f'] if args.follow else []), str(path)], check=True)
    elif args.action == "reset-admin":
        reset_admin(prefix)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"exploration: {error}", file=sys.stderr)
        raise SystemExit(1)
