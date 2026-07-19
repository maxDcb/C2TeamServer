"""Validated, public connection profiles produced by ``TeamServer init``."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ConnectionProfile:
    path: Path
    deployment_profile: str
    host: str
    port: int
    server_name: str
    root_certificates_pem: bytes
    certificate_fingerprint: str
    username: str

    @classmethod
    def load(cls, path: str | Path) -> "ConnectionProfile":
        profile_path = Path(path).expanduser().resolve()
        if not profile_path.is_file():
            raise ValueError(f"Connection profile not found: {profile_path}")
        try:
            document: dict[str, Any] = json.loads(profile_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid connection profile: {profile_path}") from exc

        if document.get("schema_version") != 1:
            raise ValueError("Unsupported connection profile schema")
        deployment_profile = document.get("profile")
        if deployment_profile not in {"development", "standalone", "production"}:
            raise ValueError("Connection profile has an invalid deployment profile")

        endpoint = document.get("endpoint")
        tls = document.get("tls")
        authentication = document.get("authentication")
        if not isinstance(endpoint, dict) or not isinstance(tls, dict) or not isinstance(authentication, dict):
            raise ValueError("Connection profile is missing required sections")

        host = endpoint.get("host")
        port = endpoint.get("port")
        server_name = tls.get("server_name")
        root_pem = tls.get("root_certificates_pem")
        fingerprint = tls.get("sha256_fingerprint")
        username = authentication.get("username")
        if not isinstance(host, str) or not host:
            raise ValueError("Connection profile endpoint host is invalid")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("Connection profile endpoint port is invalid")
        if not isinstance(server_name, str) or not server_name:
            raise ValueError("Connection profile TLS server name is invalid")
        if not isinstance(root_pem, str) or "BEGIN CERTIFICATE" not in root_pem:
            raise ValueError("Connection profile trust certificate is invalid")
        if not isinstance(fingerprint, str) or len(fingerprint) != 64:
            raise ValueError("Connection profile certificate fingerprint is invalid")
        if not isinstance(username, str) or not username:
            raise ValueError("Connection profile username is invalid")

        return cls(
            path=profile_path,
            deployment_profile=deployment_profile,
            host=host,
            port=port,
            server_name=server_name,
            root_certificates_pem=root_pem.encode("utf-8"),
            certificate_fingerprint=fingerprint.lower(),
            username=username,
        )

