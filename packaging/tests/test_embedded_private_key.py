from pathlib import Path

import pytest

import validate_release


def test_release_rejects_embedded_pem_private_key(tmp_path: Path):
    release_root = tmp_path / "Release"
    release_root.mkdir()
    payload = release_root / "renamed-secret.txt"
    payload.write_text(
        "-----BEGIN PRIVATE KEY-----\n"
        + ("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0123456789abcd" * 2)
        + "\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    with pytest.raises(validate_release.ValidationError, match="embedded private-key material"):
        validate_release.validate_base_release(release_root)
