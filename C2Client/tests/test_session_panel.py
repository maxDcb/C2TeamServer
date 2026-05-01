from PyQt6.QtWidgets import QWidget

from C2Client.SessionPanel import Sessions


class StubGrpc:
    def getSessions(self):
        return []


def test_sessions_table_labels_arch_as_beacon_process(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.SessionPanel.QThread.start", lambda self: None)

    parent = QWidget()
    sessions = Sessions(parent, StubGrpc())
    qtbot.addWidget(sessions)

    sessions.printSessions()

    arch_header = sessions.listSession.horizontalHeaderItem(4)
    assert arch_header.text() == "Beacon Arch"
    assert arch_header.toolTip() == "Architecture du process beacon"
