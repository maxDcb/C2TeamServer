from pathlib import Path

import pytest

import validate_release


@pytest.mark.parametrize(
    "relative_path",
    [
        "TeamServer/server.key",
        "TeamServer/auth_credentials.json",
        "TeamServer/bootstrap.txt",
        "Client/operator.p12",
        "data/CredentialVault/vault.key",
    ],
)
def test_release_rejects_private_deployment_material(tmp_path: Path, relative_path: str):
    release_root = tmp_path / "Release"
    release_root.mkdir()
    secret = release_root / relative_path
    secret.parent.mkdir(parents=True, exist_ok=True)
    secret.write_text("secret", encoding="utf-8")

    with pytest.raises(validate_release.ValidationError, match="private deployment material"):
        validate_release.validate_base_release(release_root)

