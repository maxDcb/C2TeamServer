import json

import pytest

from C2Client.connection_profile import ConnectionProfile


def _profile() -> dict:
    return {
        "schema_version": 1,
        "instance_id": "instance",
        "profile": "standalone",
        "endpoint": {"host": "localhost", "port": 50051},
        "tls": {
            "root_certificates_pem": "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n",
            "server_name": "localhost",
            "sha256_fingerprint": "a" * 64,
        },
        "authentication": {"username": "admin"},
    }


def test_connection_profile_loads_valid_profile(tmp_path):
    path = tmp_path / "client-profile.json"
    path.write_text(json.dumps(_profile()), encoding="utf-8")

    profile = ConnectionProfile.load(path)

    assert profile.host == "localhost"
    assert profile.port == 50051
    assert profile.username == "admin"
    assert profile.root_certificates_pem.startswith(b"-----BEGIN CERTIFICATE-----")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", 2, "schema"),
        ("profile", "legacy", "deployment profile"),
    ],
)
def test_connection_profile_rejects_invalid_contract(tmp_path, field, value, message):
    document = _profile()
    document[field] = value
    path = tmp_path / "client-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        ConnectionProfile.load(path)

