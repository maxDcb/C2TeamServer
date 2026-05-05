from types import SimpleNamespace

from PyQt6.QtWidgets import QWidget

from C2Client.CommandPanel import Commands, format_arg_summary


class FakeGrpc:
    def __init__(self):
        self.queries = []
        self.commands = [
            SimpleNamespace(
                name="sleep",
                display_name="sleep",
                kind="common",
                description="Set beacon sleep interval.",
                target="beacon",
                requires_session=True,
                platforms=["windows", "linux"],
                archs=["any"],
                args=[
                    SimpleNamespace(
                        name="seconds",
                        type="number",
                        required=True,
                        description="Sleep interval.",
                        values=[],
                        variadic=False,
                    )
                ],
                examples=["sleep 0.5"],
                source="manifest",
            ),
            SimpleNamespace(
                name="pwd",
                display_name="pwd",
                kind="module",
                description="Print current working directory.",
                target="beacon",
                requires_session=True,
                platforms=["windows", "linux"],
                archs=["any"],
                args=[],
                examples=["pwd"],
                source="manifest",
            ),
        ]

    def listCommands(self, query):
        self.queries.append(query)
        return iter(self.commands)


class FailingGrpc:
    def listCommands(self, query):
        raise RuntimeError("command catalog unavailable")


def test_format_arg_summary_handles_required_optional_and_variadic():
    command = SimpleNamespace(
        args=[
            SimpleNamespace(name="path", type="path", required=False, variadic=True),
            SimpleNamespace(name="mode", type="enum", required=True, variadic=False),
        ]
    )

    assert format_arg_summary(command) == "[path:path]... mode:enum"


def test_commands_panel_lists_filters_and_details(qtbot):
    grpc = FakeGrpc()
    parent = QWidget()
    panel = Commands(parent, grpc)
    qtbot.addWidget(panel)

    assert panel.commandTable.rowCount() == 2
    assert panel.commandTable.item(0, 0).text() == "sleep"
    assert panel.commandTable.item(0, 1).text() == "common"
    assert panel.commandTable.item(0, 4).text() == "seconds:number"
    assert panel.commandTable.item(0, 5).text() == "sleep 0.5"

    panel.kindFilter.setCurrentText("module")
    panel.targetFilter.setCurrentText("beacon")
    panel.platformFilter.setCurrentText("linux")
    panel.searchInput.setText("pwd")
    panel.refreshCommands()

    query = grpc.queries[-1]
    assert query.kind == "module"
    assert query.target == "beacon"
    assert query.platform == "linux"
    assert query.name_contains == "pwd"

    panel.commandTable.selectRow(0)
    assert "Set beacon sleep interval." in panel.details.toPlainText()
    assert "seconds" in panel.details.toPlainText()


def test_commands_panel_reports_refresh_errors(qtbot):
    parent = QWidget()
    panel = Commands(parent, FailingGrpc())
    qtbot.addWidget(panel)

    assert panel.commandTable.rowCount() == 0
    assert "command catalog unavailable" in panel.statusLabel.text()
    assert "#b00020" in panel.statusLabel.styleSheet()
