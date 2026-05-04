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


class PivotGrpc:
    def listSessions(self):
        return [
            SimpleNamespace(
                beacon_hash="beacon-parent",
                listener_hash="listener-primary",
                os="Windows",
                privilege="HIGH",
                hostname="parent",
            ),
            SimpleNamespace(
                beacon_hash="beacon-child",
                listener_hash="listener-pivot",
                os="Linux",
                privilege="user",
                hostname="child",
            ),
        ]

    def listListeners(self):
        return [
            SimpleNamespace(listener_hash="listener-primary", beacon_hash="", type="https"),
            SimpleNamespace(listener_hash="listener-pivot", beacon_hash="beacon-parent", type="tcp"),
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


def test_graph_layout_places_pivot_children_in_deeper_columns(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.GraphPanel.QThread.start", lambda self: None)

    graph = Graph(QWidget(), PivotGrpc())
    qtbot.addWidget(graph)
    graph.updateGraph()

    parent = graph.findBeaconNode("beacon-parent")
    child = graph.findBeaconNode("beacon-child")
    primary = graph.findResponsibleNode("listener-primary")

    assert primary.displayLabel.startswith("https")
    assert parent.pos().x() == graph.BEACON_X
    assert child.pos().x() == graph.SECONDARY_LISTENER_X
    assert len(graph.listConnector) == 2
    assert "Hosted listeners: listener-pivot" in parent.toolTip()
    assert "Listener: listener-pivot" in child.toolTip()


def test_graph_auto_button_reclaims_user_moved_nodes(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.GraphPanel.QThread.start", lambda self: None)

    parent = QWidget()
    qtbot.addWidget(parent)
    graph = Graph(parent, StubGrpc())
    qtbot.addWidget(graph)
    graph.updateGraph()

    moved = graph.findBeaconNode("beacon-1")
    moved.userMoved = True
    moved.setPos(QPointF(900, 700))

    graph.autoLayoutButton.click()

    assert moved.userMoved is False
    assert moved.pos().x() == graph.BEACON_X


def test_graph_zoom_buttons_update_view_scale(qtbot, monkeypatch):
    monkeypatch.setattr("C2Client.GraphPanel.QThread.start", lambda self: None)

    parent = QWidget()
    qtbot.addWidget(parent)
    graph = Graph(parent, StubGrpc())
    qtbot.addWidget(graph)

    initial_scale = graph.view.transform().m11()
    graph.zoomInButton.click()

    assert graph.view.transform().m11() > initial_scale

    graph.zoomOutButton.click()

    assert graph.view.transform().m11() == initial_scale
