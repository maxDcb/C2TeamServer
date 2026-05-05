import os
import time
import logging

from PyQt6.QtCore import QObject, QPointF, Qt, QThread, QLineF, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QFontMetrics, QPainter, QPen, QPixmap
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QGraphicsLineItem,
    QGraphicsPixmapItem,
    QGraphicsScene,
    QGraphicsView,
    QPushButton,
    QVBoxLayout,
    QWidget,
    QGraphicsItem,
)

from .env import env_int

logger = logging.getLogger(__name__)


#
# Constant
#
BeaconNodeItemType = "Beacon"
ListenerNodeItemType = "Listener"
NODE_ICON_SIZE = 64
NODE_LABEL_WIDTH = 132
NODE_TEXT_COLOR = QColor("#e4e7ec")
GRAPH_BACKGROUND_COLOR = QColor("#0b1117")
GRAPH_EDGE_COLOR = QColor("#7cd4fd")
GRAPH_ZOOM_STEP = 1.18
GRAPH_MIN_ZOOM = 0.25
GRAPH_MAX_ZOOM = 3.0

try:
    import pkg_resources
    PrimaryListenerImage = pkg_resources.resource_filename(
        'C2Client',  
        'images/firewall.svg' 
    )
    WindowsSessionImage = pkg_resources.resource_filename(
    'C2Client',  
    'images/pc.svg' 
    )
    WindowsHighPrivSessionImage = pkg_resources.resource_filename(
        'C2Client',  
        'images/windowshighpriv.svg' 
    )
    LinuxSessionImage = pkg_resources.resource_filename(
        'C2Client',  
        'images/linux.svg' 
    )
    LinuxRootSessionImage = pkg_resources.resource_filename(
        'C2Client',  
        'images/linuxhighpriv.svg' 
    )
except ImportError:
    PrimaryListenerImage = os.path.join(os.path.dirname(__file__), 'images/firewall.svg')
    WindowsSessionImage = os.path.join(os.path.dirname(__file__), 'images/pc.svg')
    WindowsHighPrivSessionImage = os.path.join(os.path.dirname(__file__), 'images/windowshighpriv.svg')
    LinuxSessionImage = os.path.join(os.path.dirname(__file__), 'images/linux.svg')
    LinuxRootSessionImage = os.path.join(os.path.dirname(__file__), 'images/linuxhighpriv.svg')


def short_hash(value, length=8):
    text = str(value or "")
    return text[:length] if len(text) > length else text


def _text(value):
    return str(value or "").strip()


#
# Graph Tab Implementation
#
# needed to send the message of mouseMoveEvent because QGraphicsPixmapItem doesn't herit from QObject
class Signaller(QObject):
    signal = pyqtSignal()

    def trigger(self):
        self.signal.emit()


class NodeItem(QGraphicsPixmapItem):
    def __init__(self, type, hash, os="", privilege="", hostname="", listener_type="", parent=None):
        # Signal to notify position changes; QGraphicsPixmapItem is not a QObject.
        self.signaller = Signaller()
        self.autoPositioned = False
        self.userMoved = False
        self.displayLabel = ""
        self.os = _text(os)
        self.privilege = _text(privilege)
        self.hostname = _text(hostname)
        self.listenerType = _text(listener_type) or "listener"
        if type == ListenerNodeItemType:
            self.type = ListenerNodeItemType
            self.displayLabel = "\n".join([self.listenerType, short_hash(hash)])
            pixmap = self.addImageNode(PrimaryListenerImage, self.displayLabel)
            self.beaconHash = ""
            self.connectedListenerHash = ""
            self.listenerHash = []
            self.listenerHash.append(hash)
        elif type == BeaconNodeItemType:
            self.type = BeaconNodeItemType
            self.displayLabel = self.beaconLabel(hash)
            if "linux" in self.os.lower():
                if self.privilege == "root":
                    pixmap = self.addImageNode(LinuxRootSessionImage, self.displayLabel)
                else:
                    pixmap = self.addImageNode(LinuxSessionImage, self.displayLabel)
            elif "windows" in self.os.lower():
                if self.privilege == "HIGH":
                    pixmap = self.addImageNode(WindowsHighPrivSessionImage, self.displayLabel)
                else:
                    pixmap = self.addImageNode(WindowsSessionImage, self.displayLabel)
            else:
                pixmap = self.addImageNode(LinuxSessionImage, self.displayLabel)
            self.beaconHash=hash
            self.connectedListenerHash = ""
            self.listenerHash=[]

        super().__init__(pixmap)
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.CursorShape.OpenHandCursor)
        self.refreshTooltip()

    def logDebug(self):
        logger.debug(
            "NodeItem %s beaconHash=%s listenerHash=%s connectedListenerHash=%s",
            self.type,
            self.beaconHash,
            self.listenerHash,
            self.connectedListenerHash,
        )

    def isResponsableForListener(self, hash):
        if hash in self.listenerHash:
            return True      
        else:
            return False

    def beaconLabel(self, beaconHash):
        if self.hostname:
            return "\n".join([self.hostname, short_hash(beaconHash)])
        return short_hash(beaconHash)

    def addListenerHash(self, listenerHash):
        if listenerHash and listenerHash not in self.listenerHash:
            self.listenerHash.append(listenerHash)
            self.refreshTooltip()

    def removeListenerHash(self, listenerHash):
        if listenerHash in self.listenerHash:
            self.listenerHash.remove(listenerHash)
            self.refreshTooltip()

    def setConnectedListenerHash(self, listenerHash):
        self.connectedListenerHash = _text(listenerHash)
        self.refreshTooltip()

    def refreshTooltip(self):
        if self.type == ListenerNodeItemType:
            tooltip = [
                "Primary listener",
                f"Type: {self.listenerType}",
                f"Hash: {', '.join(self.listenerHash)}",
            ]
        else:
            tooltip = [
                "Beacon session",
                f"Host: {self.hostname or 'unknown'}",
                f"Hash: {self.beaconHash}",
                f"Listener: {self.connectedListenerHash or 'unknown'}",
            ]
            if self.os:
                tooltip.append(f"OS: {self.os}")
            if self.privilege:
                tooltip.append(f"Privilege: {self.privilege}")
            if self.listenerHash:
                tooltip.append(f"Hosted listeners: {', '.join(self.listenerHash)}")
        self.setToolTip("\n".join(tooltip))

    def mouseMoveEvent(self, event):
        self.userMoved = True
        self.autoPositioned = False
        super().mouseMoveEvent(event)
        self.signaller.trigger() 

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        self.setCursor(Qt.CursorShape.ClosedHandCursor)

    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
        self.setCursor(Qt.CursorShape.ArrowCursor)

    def addImageNode(self, image_path, legend_text, font_size=9, padding=5, text_color=NODE_TEXT_COLOR):
        # Load and scale the image
        pixmap = QPixmap(image_path).scaled(
            NODE_ICON_SIZE,
            NODE_ICON_SIZE,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )

        font = QFont()
        font.setPointSize(font_size)
        metrics = QFontMetrics(font)
        labelLines = [
            metrics.elidedText(line, Qt.TextElideMode.ElideRight, NODE_LABEL_WIDTH - padding * 2)
            for line in str(legend_text or "").splitlines()
            if line
        ]

        # Create a new QPixmap larger than the original for the image and text
        legend_height = (metrics.height() * len(labelLines) + padding * 2) if labelLines else 0
        combined_pixmap = QPixmap(max(NODE_LABEL_WIDTH, pixmap.width()), pixmap.height() + legend_height)
        combined_pixmap.fill(Qt.GlobalColor.transparent)  # Transparent background

        # Paint the image and the legend onto the combined pixmap
        painter = QPainter(combined_pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        image_x = (combined_pixmap.width() - pixmap.width()) // 2
        painter.drawPixmap(image_x, 0, pixmap)  # Draw the image

        pen = QPen()
        pen.setColor(text_color)  # Set the desired text color
        painter.setPen(pen)
        # Set font for the legend
        painter.setFont(font)

        # Draw the legend text centered below the image
        for index, line in enumerate(labelLines):
            line_y = pixmap.height() + padding + index * metrics.height()
            painter.drawText(
                0,
                line_y,
                combined_pixmap.width(),
                metrics.height(),
                Qt.AlignmentFlag.AlignCenter,
                line,
            )

        painter.end()
        return combined_pixmap
        

class Connector(QGraphicsLineItem):

    def __init__(self, listener, beacon, pen=None):
        super().__init__()
        self.listener = listener
        self.beacon = beacon

        self.pen = pen or QPen(GRAPH_EDGE_COLOR, 2)
        self.pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        self.setPen(self.pen)
        self.update_line()

    def logDebug(self):
        logger.debug(
            "Connector beaconHash=%s connectedListenerHash=%s listenerHash=%s",
            self.beacon.beaconHash,
            self.beacon.connectedListenerHash,
            self.listener.listenerHash,
        )

    def update_line(self):
        center1 = self.listener.pos() + self.listener.boundingRect().center()
        center2 = self.beacon.pos() + self.beacon.boundingRect().center()
        self.setLine(QLineF(center1, center2))
        
        
class Graph(QWidget):
    PRIMARY_LISTENER_X = 40
    NODE_X_GAP = 220
    BEACON_X = PRIMARY_LISTENER_X + NODE_X_GAP
    SECONDARY_LISTENER_X = BEACON_X + NODE_X_GAP
    NODE_Y_START = 40
    NODE_Y_GAP = 120

    listNodeItem = []
    listConnector = []

    def __init__(self, parent, grpcClient):
        super(QWidget, self).__init__(parent)
        
        self.grpcClient = grpcClient
        self.listNodeItem = []
        self.listConnector = []
        self.zoomFactor = 1.0

        self.scene = QGraphicsScene()
        self.scene.setBackgroundBrush(GRAPH_BACKGROUND_COLOR)

        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.view.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        self.view.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.view.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.view.setStyleSheet("QGraphicsView { border: 1px solid #263241; }")

        self.vbox = QVBoxLayout()
        self.vbox.setContentsMargins(4, 4, 4, 4)
        self.vbox.setSpacing(4)
        self.toolbar = QHBoxLayout()
        self.toolbar.setSpacing(4)
        self.toolbar.addStretch(1)
        self.refreshButton = self.createToolbarButton("Refresh", "Refresh graph now.", width=70)
        self.refreshButton.clicked.connect(self.updateGraph)
        self.toolbar.addWidget(self.refreshButton)
        self.autoLayoutButton = self.createToolbarButton("Auto", "Re-apply automatic layout.", width=56)
        self.autoLayoutButton.clicked.connect(self.resetAutoLayout)
        self.toolbar.addWidget(self.autoLayoutButton)
        self.fitButton = self.createToolbarButton("Fit", "Fit graph in view.", width=48)
        self.fitButton.clicked.connect(self.fitGraph)
        self.toolbar.addWidget(self.fitButton)
        self.zoomOutButton = self.createToolbarButton("-", "Zoom out.", width=34)
        self.zoomOutButton.clicked.connect(self.zoomOut)
        self.toolbar.addWidget(self.zoomOutButton)
        self.zoomInButton = self.createToolbarButton("+", "Zoom in.", width=34)
        self.zoomInButton.clicked.connect(self.zoomIn)
        self.toolbar.addWidget(self.zoomInButton)
        self.vbox.addLayout(self.toolbar)
        self.vbox.addWidget(self.view)

        self.setLayout(self.vbox)

        self.thread = QThread()
        self.getGraphInfoWorker = GetGraphInfoWorker()
        self.getGraphInfoWorker.moveToThread(self.thread)
        self.thread.started.connect(self.getGraphInfoWorker.run)
        self.getGraphInfoWorker.checkin.connect(self.updateGraph)
        self.thread.start()

        # self.updateScene()
        
    def createToolbarButton(self, text, tooltip, width=58):
        button = QPushButton(text)
        button.setToolTip(tooltip)
        button.setFixedHeight(26)
        button.setMinimumWidth(width)
        button.setMaximumWidth(width)
        return button


    def __del__(self):
        try:
            self.getGraphInfoWorker.quit()
            self.thread.quit()
            self.thread.wait()
        except RuntimeError:
            pass

 
    def updateConnectors(self):
        for connector in self.listConnector:
            connector.update_line()

    def resetAutoLayout(self):
        for item in self.listNodeItem:
            item.userMoved = False
        self.applyAutoLayout()
        self.fitGraph()

    def fitGraph(self):
        if not self.scene.items():
            return
        rect = self.scene.itemsBoundingRect().adjusted(-80, -80, 160, 160)
        self.scene.setSceneRect(rect)
        self.view.fitInView(rect, Qt.AspectRatioMode.KeepAspectRatio)
        self.zoomFactor = self.view.transform().m11()

    def setZoom(self, zoomFactor):
        boundedZoom = max(GRAPH_MIN_ZOOM, min(GRAPH_MAX_ZOOM, zoomFactor))
        self.zoomFactor = boundedZoom
        self.view.resetTransform()
        self.view.scale(boundedZoom, boundedZoom)

    def zoomIn(self):
        self.setZoom(self.zoomFactor * GRAPH_ZOOM_STEP)

    def zoomOut(self):
        self.setZoom(self.zoomFactor / GRAPH_ZOOM_STEP)

    def applyAutoLayout(self):
        columns = self.layoutColumns()
        for depth, nodes in columns.items():
            self.positionNodeColumn(nodes, self.PRIMARY_LISTENER_X + depth * self.NODE_X_GAP)
        self.updateConnectors()
        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-80, -80, 160, 160))

    def layoutColumns(self):
        listenerDepthByHash = {}
        columns = {0: []}

        for item in self.listNodeItem:
            if item.type == ListenerNodeItemType:
                columns[0].append(item)
                for listenerHash in item.listenerHash:
                    listenerDepthByHash[listenerHash] = 0

        beaconDepthByHash = {}
        beacons = [
            item for item in self.listNodeItem
            if item.type == BeaconNodeItemType
        ]

        changed = True
        remainingPasses = max(1, len(beacons) + len(listenerDepthByHash) + 1)
        while changed and remainingPasses > 0:
            remainingPasses -= 1
            changed = False
            for beacon in beacons:
                sourceDepth = listenerDepthByHash.get(beacon.connectedListenerHash, 0)
                depth = max(1, sourceDepth + 1)
                if beaconDepthByHash.get(beacon.beaconHash) != depth:
                    beaconDepthByHash[beacon.beaconHash] = depth
                    changed = True
                for listenerHash in beacon.listenerHash:
                    if listenerDepthByHash.get(listenerHash) != depth:
                        listenerDepthByHash[listenerHash] = depth
                        changed = True

        for beacon in beacons:
            depth = beaconDepthByHash.get(beacon.beaconHash, 1)
            columns.setdefault(depth, []).append(beacon)

        for depth, nodes in columns.items():
            columns[depth] = sorted(nodes, key=lambda item: (item.type, item.displayLabel, item.beaconHash))
        return columns

    def positionNodeColumn(self, nodes, x):
        for index, node in enumerate(nodes):
            if node.userMoved:
                continue
            node.setPos(QPointF(x, self.NODE_Y_START + index * self.NODE_Y_GAP))
            node.autoPositioned = True

    def findBeaconNode(self, beaconHash):
        for nodeItem in self.listNodeItem:
            if nodeItem.type == BeaconNodeItemType and nodeItem.beaconHash == beaconHash:
                return nodeItem
        return None

    def findResponsibleNode(self, listenerHash):
        for nodeItem in self.listNodeItem:
            if nodeItem.isResponsableForListener(listenerHash):
                return nodeItem
        return None

    def removeNode(self, nodeItem):
        for connector in list(self.listConnector):
            if connector.listener is nodeItem or connector.beacon is nodeItem:
                self.scene.removeItem(connector)
                self.listConnector.remove(connector)
        if nodeItem in self.listNodeItem:
            self.scene.removeItem(nodeItem)
            self.listNodeItem.remove(nodeItem)

    def syncBeacons(self, sessions):
        sessionHashes = {session.beacon_hash for session in sessions}
        for nodeItem in list(self.listNodeItem):
            if nodeItem.type == BeaconNodeItemType and nodeItem.beaconHash not in sessionHashes:
                logger.debug("Delete graph beacon %s", nodeItem.beaconHash)
                self.removeNode(nodeItem)

        for session in sessions:
            nodeItem = self.findBeaconNode(session.beacon_hash)
            if nodeItem is None:
                nodeItem = NodeItem(
                    BeaconNodeItemType,
                    session.beacon_hash,
                    getattr(session, "os", ""),
                    getattr(session, "privilege", ""),
                    getattr(session, "hostname", ""),
                )
                nodeItem.signaller.signal.connect(self.updateConnectors)
                self.scene.addItem(nodeItem)
                self.listNodeItem.append(nodeItem)
                logger.debug("Add graph beacon %s", session.beacon_hash)
            nodeItem.setConnectedListenerHash(getattr(session, "listener_hash", ""))

    def syncListeners(self, listeners):
        activeListenerHashes = {listener.listener_hash for listener in listeners}

        for nodeItem in list(self.listNodeItem):
            if nodeItem.type == ListenerNodeItemType:
                if not any(listenerHash in activeListenerHashes for listenerHash in nodeItem.listenerHash):
                    logger.debug("Delete graph primary listener %s", nodeItem.listenerHash)
                    self.removeNode(nodeItem)
            elif nodeItem.type == BeaconNodeItemType:
                for listenerHash in list(nodeItem.listenerHash):
                    if listenerHash not in activeListenerHashes:
                        logger.debug("Delete graph secondary listener %s", listenerHash)
                        nodeItem.removeListenerHash(listenerHash)

        for listener in listeners:
            if self.findResponsibleNode(listener.listener_hash) is not None:
                continue

            beaconHash = getattr(listener, "beacon_hash", "")
            if not beaconHash:
                item = NodeItem(
                    ListenerNodeItemType,
                    listener.listener_hash,
                    listener_type=getattr(listener, "type", "listener"),
                )
                item.signaller.signal.connect(self.updateConnectors)
                self.scene.addItem(item)
                self.listNodeItem.append(item)
                logger.debug("Add graph primary listener %s", listener.listener_hash)
            else:
                beaconNode = self.findBeaconNode(beaconHash)
                if beaconNode is not None:
                    beaconNode.addListenerHash(listener.listener_hash)
                    logger.debug("Add graph secondary listener %s", listener.listener_hash)

    def rebuildConnectors(self):
        for connector in list(self.listConnector):
            self.scene.removeItem(connector)
        self.listConnector = []

        for nodeItem in self.listNodeItem:
            if nodeItem.type != BeaconNodeItemType:
                continue
            listener = self.findResponsibleNode(nodeItem.connectedListenerHash)
            if listener is None:
                continue
            connector = Connector(listener, nodeItem)
            self.scene.addItem(connector)
            connector.setZValue(-1)
            self.listConnector.append(connector)
            logger.debug(
                "Add graph connector listener=%s beacon=%s",
                nodeItem.connectedListenerHash,
                nodeItem.beaconHash,
            )

    # Update the graph with information from the team server
    def updateGraph(self):
        responses = self.grpcClient.listSessions()
        sessions = list()
        for response in responses:
            sessions.append(response)

        responses = self.grpcClient.listListeners()
        listeners = list()
        for listener in responses:
            listeners.append(listener)

        self.syncBeacons(sessions)
        self.syncListeners(listeners)
        self.rebuildConnectors()

        for item in self.listNodeItem:
            item.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
            item.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.applyAutoLayout()

        
class GetGraphInfoWorker(QObject):
    checkin = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.exit = False
        self.refreshIntervalSeconds = env_int("C2_GRAPH_REFRESH_MS", 2000, minimum=100) / 1000

    def __del__(self):
        self.exit=True

    def run(self):
        try: 
            while self.exit==False:
                if self.receivers(self.checkin) > 0:
                    self.checkin.emit()
                time.sleep(self.refreshIntervalSeconds)
        except Exception:
            logger.exception("Graph refresh worker stopped unexpectedly")

    def quit(self):
        self.exit=True
