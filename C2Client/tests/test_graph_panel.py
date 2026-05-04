from types import SimpleNamespace

from PyQt6.QtCore import QPointF
from PyQt6.QtWidgets import QWidget

from C2Client.GraphPanel import BeaconNodeItemType, Graph, ListenerNodeItemType


class StubGrpc:
    def listSessions(self):
        return [
            SimpleNamespace(
                beacon_hash="beacon-1",
                listener_hash="listener-1",
                os="Windows",
                privilege="HIGH",
                hostname="host1",
            ),
            SimpleNamespace(
                beacon_hash="beacon-2",
                listener_hash="listener-2",
                os="Linux",
                privilege="user",
                hostname="host2",
            ),
        ]

    def listListeners(self):
        return [
            SimpleNamespace(listener_hash="listener-1", beacon_hash=""),
            SimpleNamespace(listener_hash="listener-2", beacon_hash=""),
        ]


def test_graph_auto_layout_separates_new_nodes(qtbot, monkeypatch, capsys):
    monkeypatch.setattr("C2Client.GraphPanel.QThread.start", lambda self: None)

    graph = Graph(QWidget(), StubGrpc())
    qtbot.addWidget(graph)

    graph.updateGraph()
    captured = capsys.readouterr()

    listeners = [node for node in graph.listNodeItem if node.type == ListenerNodeItemType]
    beacons = [node for node in graph.listNodeItem if node.type == BeaconNodeItemType]

    assert captured.out == ""
    assert len(listeners) == 2
    assert len(beacons) == 2
    assert len({(node.pos().x(), node.pos().y()) for node in graph.listNodeItem}) == 4
    assert all(node.pos() != QPointF(0, 0) for node in graph.listNodeItem)
    assert {node.pos().x() for node in listeners} == {graph.PRIMARY_LISTENER_X}
    assert {node.pos().x() for node in beacons} == {graph.BEACON_X}


def test_graph_auto_layout_preserves_user_moved_nodes(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.GraphPanel.QThread.start", lambda self: None)

    graph = Graph(QWidget(), StubGrpc())
    qtbot.addWidget(graph)
    graph.updateGraph()

    moved = graph.listNodeItem[0]
    moved.userMoved = True
    moved.setPos(QPointF(900, 700))

    graph.updateGraph()

    assert moved.pos() == QPointF(900, 700)
