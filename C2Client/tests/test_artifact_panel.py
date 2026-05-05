from types import SimpleNamespace

from PyQt6.QtWidgets import QApplication, QWidget

from C2Client.ArtifactPanel import Artifacts, format_size


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
                platform="windows",
                arch="x64",
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
                platform="any",
                arch="any",
                format="py",
                source="release",
                size=12,
                sha256="b" * 64,
                description="Startup hook",
            ),
        ]

    def listArtifacts(self, query):
        self.queries.append(query)
        return iter(self.artifacts)


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

    assert panel.artifactTable.rowCount() == 2
    assert panel.artifactTable.item(0, 0).text() == "module"
    assert panel.artifactTable.item(0, 1).text() == "winmod64.dll"
    assert panel.artifactTable.item(0, 5).text() == "2.0 KB"
    assert panel.artifactTable.item(0, 6).text() == "aaaaaaaaaaaa"
    assert "Artifact ID: artifact-module-1" in panel.artifactTable.item(0, 1).toolTip()

    panel.categoryFilter.setCurrentText("module")
    panel.platformFilter.setCurrentText("windows")
    panel.archFilter.setCurrentText("x64")
    panel.searchInput.setText("win")
    panel.refreshArtifacts()

    query = grpc.queries[-1]
    assert query.category == "module"
    assert query.platform == "windows"
    assert query.arch == "x64"
    assert query.name_contains == "win"

    panel.artifactTable.selectRow(0)
    panel.copyIdButton.click()

    assert QApplication.clipboard().text() == "artifact-module-1"
    assert panel.statusLabel.text() == "Artifacts: artifact ID copied."


def test_artifacts_panel_reports_refresh_errors(qtbot):
    parent = QWidget()
    panel = Artifacts(parent, FailingGrpc())
    qtbot.addWidget(panel)

    assert panel.artifactTable.rowCount() == 0
    assert "catalog unavailable" in panel.statusLabel.text()
    assert "#b00020" in panel.statusLabel.styleSheet()
