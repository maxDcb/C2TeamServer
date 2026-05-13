from types import SimpleNamespace

import C2Client.grpcClient as grpc_client_module
import sys
sys.modules['grpcClient'] = grpc_client_module

import C2Client.CredentialVaultPanel as credential_vault_panel
from C2Client.CredentialVaultPanel import (
    CredentialEntryDialog,
    CredentialVault,
    first_secret_value,
    secret_name_for_type,
)
from C2Client.grpcClient import TeamServerApi_pb2


def _summary(**overrides):
    values = {
        "credential_id": "abcdef1234567890",
        "display_name": "corp alice",
        "type": "password",
        "username": "CORP\\alice",
        "domain": "",
        "realm": "",
        "target": "",
        "protocol": "",
        "tags": [],
        "description": "local admin",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
        "last_used_at": "",
        "expires_at": "",
        "secret_fields": ["password"],
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class FakeGrpc:
    def __init__(self):
        self.queries = []
        self.added = []
        self.updated = []
        self.deleted = []
        self.revealed = None
        self.reveal_calls = []
        self.credentials = [_summary()]
        self.detail = SimpleNamespace(
            status=TeamServerApi_pb2.OK,
            message="",
            summary=self.credentials[0],
            secrets=[
                SimpleNamespace(name="password", value="Secret123!"),
            ],
        )

    def listCredentials(self, query):
        self.queries.append(query)
        return iter(self.credentials)

    def getCredential(self, credential_id, reveal_secret=False):
        self.revealed = (credential_id, reveal_secret)
        self.reveal_calls.append((credential_id, reveal_secret))
        return self.detail

    def addCredential(self, request):
        self.added.append(request)
        return SimpleNamespace(status=TeamServerApi_pb2.OK, message="Credential stored.")

    def updateCredential(self, request):
        self.updated.append(request)
        return SimpleNamespace(status=TeamServerApi_pb2.OK, message="Credential updated.")

    def deleteCredential(self, credential_id):
        self.deleted.append(credential_id)
        return SimpleNamespace(status=TeamServerApi_pb2.OK, message="Credential deleted.")


def _entry_values(**overrides):
    values = {
        "title": "corp alice",
        "username": "CORP\\alice",
        "type": "password",
        "secret_name": "password",
        "secret": "",
        "description": "local admin",
    }
    values.update(overrides)
    return values


def test_credential_vault_panel_lists_like_keepass_and_filters(qtbot):
    grpc = FakeGrpc()
    panel = CredentialVault(None, grpc)
    qtbot.addWidget(panel)

    assert panel.credentialTable.rowCount() == 1
    assert panel.credentialTable.item(0, 0).text() == "corp alice"
    assert panel.credentialTable.item(0, 1).text() == "CORP\\alice"
    assert panel.credentialTable.item(0, 2).text() == "password"
    assert panel.credentialTable.item(0, 3).text() == "••••••••"
    assert panel.credentialTable.item(0, 4).text() == "local admin"
    assert panel.credentialTable.item(0, 5).text() == "2026-01-02T00:00:00Z"
    assert panel.selectedCredentialId == "abcdef1234567890"

    panel.credentialTable.selectRow(0)
    assert panel.detailTitleLabel.text() == "corp alice"
    assert panel.detailUsernameLabel.text() == "CORP\\alice"
    assert panel.detailTypeLabel.text() == "password"
    assert panel.detailSecretLabel.text() == "••••••••"
    assert panel.detailSecretLabel.isReadOnly() is True
    assert panel.detailNotesLabel.text() == "local admin"

    panel.typeFilter.setCurrentText("ntlm_hash")
    panel.usernameFilter.setText("alice")
    panel.searchInput.setText("corp")

    grpc.queries.clear()
    panel.refreshCredentials()
    query = grpc.queries[-1]

    assert query.type == "ntlm_hash"
    assert query.username == "alice"
    assert query.name_contains == "corp"
    assert query.domain == ""
    assert query.target == ""
    assert query.protocol == ""
    assert query.tag == ""
    assert query.include_expired is False


def test_credential_vault_panel_deletes_single_entry_without_manual_selection(qtbot, monkeypatch):
    grpc = FakeGrpc()
    panel = CredentialVault(None, grpc)
    qtbot.addWidget(panel)

    monkeypatch.setattr(
        credential_vault_panel.QMessageBox,
        "question",
        lambda *args, **kwargs: credential_vault_panel.QMessageBox.StandardButton.Yes,
    )

    assert panel.selectedCredentialId == "abcdef1234567890"
    assert panel.deleteButton.isEnabled() is True

    panel.deleteSelectedCredential()

    assert grpc.deleted == ["abcdef1234567890"]


def test_credential_vault_panel_adds_single_secret_entry(qtbot, monkeypatch):
    grpc = FakeGrpc()
    panel = CredentialVault(None, grpc)
    qtbot.addWidget(panel)

    monkeypatch.setattr(
        panel,
        "runEntryDialog",
        lambda **_kwargs: _entry_values(
            title="ssh alice",
            username="alice",
            type="ssh_key",
            secret_name="",
            secret="KEYDATA",
            description="ssh private key\nhost: linux01",
        ),
    )

    panel.addCredential()
    request = grpc.added[-1]

    assert request.display_name == "ssh alice"
    assert request.username == "alice"
    assert request.type == "ssh_key"
    assert request.description == "ssh private key\nhost: linux01"
    assert request.domain == ""
    assert request.realm == ""
    assert request.target == ""
    assert request.protocol == ""
    assert list(request.tags) == []
    assert request.expires_at == ""
    assert request.replace_secrets is True
    assert request.secrets[0].name == "private_key"
    assert request.secrets[0].value == "KEYDATA"


def test_credential_vault_panel_edits_without_replacing_secret(qtbot, monkeypatch):
    grpc = FakeGrpc()
    panel = CredentialVault(None, grpc)
    qtbot.addWidget(panel)
    panel.credentialTable.selectRow(0)

    monkeypatch.setattr(
        panel,
        "runEntryDialog",
        lambda **_kwargs: _entry_values(title="updated title", secret=""),
    )

    panel.editSelectedCredential()
    request = grpc.updated[-1]

    assert grpc.revealed == ("abcdef1234567890", True)
    assert request.credential_id == "abcdef1234567890"
    assert request.display_name == "updated title"
    assert len(request.secrets) == 0
    assert request.replace_secrets is False


def test_credential_vault_panel_edit_reveals_and_updates_single_secret(qtbot, monkeypatch):
    grpc = FakeGrpc()
    panel = CredentialVault(None, grpc)
    qtbot.addWidget(panel)
    panel.credentialTable.selectRow(0)

    calls = []

    def fake_dialog(**kwargs):
        calls.append(kwargs)
        return _entry_values(secret_name="password", secret="UpdatedSecret!")

    monkeypatch.setattr(panel, "runEntryDialog", fake_dialog)

    panel.editSelectedCredential()
    request = grpc.updated[-1]

    assert grpc.revealed == ("abcdef1234567890", True)
    assert calls[0]["secret_value"] == "Secret123!"
    assert request.credential_id == "abcdef1234567890"
    assert request.replace_secrets is True
    assert request.secrets[0].name == "password"
    assert request.secrets[0].value == "UpdatedSecret!"


def test_credential_vault_panel_detail_reveals_secret_without_editing(qtbot):
    grpc = FakeGrpc()
    panel = CredentialVault(None, grpc)
    qtbot.addWidget(panel)
    panel.credentialTable.selectRow(0)

    panel.revealDetailSecret()

    assert grpc.revealed == ("abcdef1234567890", True)
    assert grpc.reveal_calls == [("abcdef1234567890", True)]
    assert panel.detailSecretLabel.text() == "Secret123!"
    assert panel.detailRevealButton.text() == "Hide"
    assert grpc.updated == []

    panel.revealDetailSecret()

    assert grpc.reveal_calls == [("abcdef1234567890", True)]
    assert panel.detailSecretLabel.text() == "••••••••"
    assert panel.detailRevealButton.text() == "Reveal"
    assert grpc.updated == []


def test_credential_vault_panel_deletes_with_confirmation(qtbot, monkeypatch):
    grpc = FakeGrpc()
    panel = CredentialVault(None, grpc)
    qtbot.addWidget(panel)
    panel.credentialTable.selectRow(0)

    monkeypatch.setattr(
        credential_vault_panel.QMessageBox,
        "question",
        lambda *args, **kwargs: credential_vault_panel.QMessageBox.StandardButton.Yes,
    )

    panel.deleteSelectedCredential()

    assert grpc.deleted == ["abcdef1234567890"]


def test_credential_vault_secret_helpers():
    assert secret_name_for_type("password") == "password"
    assert secret_name_for_type("ntlm_hash") == "ntlm"
    assert secret_name_for_type("ssh_key") == "private_key"
    assert secret_name_for_type("custom", "api_key") == "api_key"
    assert first_secret_value([SimpleNamespace(name="token", value="abc")]) == ("token", "abc")


def test_credential_entry_dialog_opens_at_comfortable_size(qtbot):
    dialog = CredentialEntryDialog(None, title="Edit Credential", require_secret=False)
    qtbot.addWidget(dialog)

    assert dialog.minimumWidth() >= 680
    assert dialog.minimumHeight() >= 480
    assert dialog.notesInput.minimumHeight() >= 150
