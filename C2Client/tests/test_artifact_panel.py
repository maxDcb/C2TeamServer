from types import SimpleNamespace

from PyQt6.QtWidgets import QApplication, QMessageBox, QWidget

from C2Client.ArtifactPanel import Artifacts, format_size
from C2Client.grpcClient import TeamServerApi_pb2


class FakeGrpc:
    def __init__(self):
        self.queries = []
        self.artifacts = [
            SimpleNamespace(
                artifact_id="artifact-module-1",
                name="winmod64.dll",
                display_name="winmod64.dll",
                category="module",
                scope="beacon",
                target="beacon",
                platform="windows",
                arch="x64",
                runtime="native",
                format="dll",
                source="release",
                size=2048,
                sha256="a" * 64,
                description="Windows module",
            ),
            SimpleNamespace(
                artifact_id="artifact-script-1",
                name="startup.py",
                display_name="startup.py",
                category="script",
                scope="teamserver",
                target="teamserver",
                platform="any",
                arch="any",
                runtime="python",
                format="py",
                source="release",
                size=12,
                sha256="b" * 64,
                description="Startup hook",
            ),
            SimpleNamespace(
                artifact_id="artifact-generated-1",
                name="9d4c1e5f0a3b-Rubeus.exe.bin",
                display_name="Rubeus.exe.bin",
                category="payload",
                scope="generated",
                target="beacon",
                platform="windows",
                arch="x64",
                runtime="shellcode",
                format="bin",
                source="donut",
                size=4096,
                sha256="c" * 64,
                description="Generated shellcode for assemblyExec.",
            ),
        ]
        self.deleted = []

    def listArtifacts(self, query):
        self.queries.append(query)

        def matches(artifact, field):
            expected = getattr(query, field, "")
            if not expected:
                return True
            actual = getattr(artifact, field, "")
            return actual == expected or actual == "any"

        def name_matches(artifact):
            expected = getattr(query, "name_contains", "")
            if not expected:
                return True
            return expected.lower() in getattr(artifact, "name", "").lower()

        return iter([
            artifact for artifact in self.artifacts
            if matches(artifact, "category")
            and matches(artifact, "scope")
            and matches(artifact, "target")
            and matches(artifact, "platform")
            and matches(artifact, "arch")
            and matches(artifact, "runtime")
            and name_matches(artifact)
        ])

    def deleteGeneratedArtifact(self, artifact_id):
        self.deleted.append(artifact_id)
        self.artifacts = [
            artifact for artifact in self.artifacts
            if artifact.artifact_id != artifact_id
        ]
        return SimpleNamespace(status=TeamServerApi_pb2.OK, message="Generated artifact deleted.")


class FailingGrpc:
    def listArtifacts(self, query):
        raise RuntimeError("catalog unavailable")


def test_format_size_uses_human_units():
    assert format_size(0) == "0 B"
    assert format_size(42) == "42 B"
    assert format_size(2048) == "2.0 KB"
    assert format_size(1024 * 1024) == "1.0 MB"


def test_artifacts_panel_lists_filters_and_copies_id(qtbot):
    grpc = FakeGrpc()
    parent = QWidget()
    panel = Artifacts(parent, grpc)
    qtbot.addWidget(panel)

    assert panel.categoryFilter.findText("minidump") != -1
    assert panel.categoryFilter.findText("screenshot") != -1
    assert panel.artifactTable.rowCount() == 3
    assert panel.artifactTable.item(0, 0).text() == "module"
    assert panel.artifactTable.item(0, 1).text() == "beacon"
    assert panel.artifactTable.item(0, 2).text() == "beacon"
    assert panel.artifactTable.item(0, 3).text() == "winmod64.dll"
    assert panel.artifactTable.item(0, 6).text() == "native"
    assert panel.artifactTable.item(0, 8).text() == "2.0 KB"
    assert panel.artifactTable.item(0, 9).text() == "aaaaaaaaaaaa"
    assert "Artifact ID: artifact-module-1" in panel.artifactTable.item(0, 3).toolTip()

    panel.categoryFilter.setCurrentText("module")
    panel.scopeFilter.setCurrentText("beacon")
    panel.targetFilter.setCurrentText("beacon")
    panel.platformFilter.setCurrentText("windows")
    panel.archFilter.setCurrentText("x64")
    panel.runtimeFilter.setCurrentText("native")
    panel.searchInput.setText("win")
    panel.refreshArtifacts()

    query = grpc.queries[-1]
    assert query.category == "module"
    assert query.scope == "beacon"
    assert query.target == "beacon"
    assert query.platform == "windows"
    assert query.arch == "x64"
    assert query.runtime == "native"
    assert query.name_contains == "win"

    panel.artifactTable.selectRow(0)
    panel.copyIdButton.click()

    assert QApplication.clipboard().text() == "artifact-module-1"
    assert panel.statusLabel.text() == "Artifacts: artifact ID copied."
    assert not panel.deleteButton.isEnabled()


def test_artifacts_panel_filters_generated_shellcodes_and_deletes(qtbot, monkeypatch):
    grpc = FakeGrpc()
    parent = QWidget()
    panel = Artifacts(parent, grpc)
    qtbot.addWidget(panel)

    panel.generatedButton.click()

    query = grpc.queries[-1]
    assert query.category == "payload"
    assert query.scope == "generated"
    assert query.runtime == "shellcode"
    assert panel.artifactTable.rowCount() == 1
    assert panel.artifactTable.item(0, 1).text() == "generated"
    assert panel.artifactTable.item(0, 10).text() == "donut"
    assert "SHA256: " + ("c" * 64) in panel.artifactTable.item(0, 3).toolTip()

    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )
    panel.artifactTable.selectRow(0)
    assert panel.deleteButton.isEnabled()
    panel.deleteButton.click()

    assert grpc.deleted == ["artifact-generated-1"]
    assert panel.artifactTable.rowCount() == 0
    assert panel.statusLabel.text() == "Artifacts: Generated artifact deleted."


def test_artifacts_panel_reports_refresh_errors(qtbot):
    parent = QWidget()
    panel = Artifacts(parent, FailingGrpc())
    qtbot.addWidget(panel)

    assert panel.artifactTable.rowCount() == 0
    assert "catalog unavailable" in panel.statusLabel.text()
    assert "#b00020" in panel.statusLabel.styleSheet()
