import sys
import os
import time
from threading import Thread, Lock
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtGui import QPixmap, QTransform

from grpcClient import *


# https://www.pythonguis.com/tutorials/pyqt-qgraphics-vector-graphics/
# https://github.com/HavocFramework/Havoc/blob/a3f36e843b4df7f7f9124c68e61c137811c87ee5/client/include/UserInterface/Widgets/SessionGraph.hpp#L87


class Signaller(QObject):
    signal = pyqtSignal()

    def trigger(self):
        self.signal.emit()


class MovablePixmapItem(QGraphicsPixmapItem):
    # Signal to notify position changes
    signaller = Signaller()

    def __init__(self, pixmap, parent=None):
        super().__init__(pixmap)

    def mouseMoveEvent(self, event):
        print(event)
        super().mouseMoveEvent(event)
        self.signaller.trigger()  # Emit signal when moved

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        self.setCursor(Qt.ClosedHandCursor)

    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
        self.setCursor(Qt.ArrowCursor)


class Graph(QWidget):

    def __init__(self, parent, ip, port, devMode):
        super(QWidget, self).__init__(parent)
        
        width = self.frameGeometry().width()
        height = self.frameGeometry().height()

        self.ip = ip
        self.port = port
        self.grpcClient = GrpcClient(ip, port, devMode)

        self.scene = QGraphicsScene()


        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.Antialiasing)  

        self.vbox = QVBoxLayout()
        self.vbox.setContentsMargins(0, 0, 0, 0)
        self.vbox.addWidget(self.view)

        self.setLayout(self.vbox)


        # Thread to get listeners every second
        # https://realpython.com/python-pyqt-qthread/
        self.thread = QThread()
        self.getGraphInfoWorker = GetGraphInfoWorker()
        self.getGraphInfoWorker.moveToThread(self.thread)
        self.thread.started.connect(self.getGraphInfoWorker.run)
        self.getGraphInfoWorker.checkin.connect(self.updateGraph)
        self.thread.start()

        self.updateScene()
        

    def __del__(self):
        self.getGraphInfoWorker.quit()
        self.thread.quit()
        self.thread.wait()


    def updateScene(self):
        # Create the first movable QPixmap
        pixmap1 = QPixmap("firewall.png").scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.item1 = MovablePixmapItem(pixmap1)
        self.item1.setPos(100, 50)
        self.scene.addItem(self.item1)

        # Create the second movable QPixmap
        pixmap2 = QPixmap("pc.png").scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.item2 = MovablePixmapItem(pixmap2)
        self.item2.setPos(300, 150)
        self.scene.addItem(self.item2)

        # Draw the line between the centers of the two pixmaps
        self.line = self.scene.addLine(0, 0, 0, 0, QPen(Qt.black, 2))
        self.update_line()

        # Connect the positionChanged signal to update_line
        self.item1.signaller.signal.connect(self.update_line)
        self.item2.signaller.signal.connect(self.update_line)

        # Set all items as moveable and selectable.
        for item in self.scene.items():
            item.setFlag(QGraphicsItem.ItemIsMovable)
            item.setFlag(QGraphicsItem.ItemIsSelectable)

 
    def update_line(self):
        # Update the line to connect the centers of the two pixmaps
        center1 = self.item1.pos() + self.item1.boundingRect().center()
        center2 = self.item2.pos() + self.item2.boundingRect().center()
        self.line.setLine(center1.x(), center1.y(), center2.x(), center2.y())


    # query the server to get the list of listeners
    def updateGraph(self):
        listeners = self.grpcClient.getListeners()

        sessions = self.grpcClient.getSessions()

        # pixmap = QPixmap("pc.png")
        # pixmap = pixmap.scaled(64, 64)
        # pixmapitem = self.scene.addPixmap(pixmap)
        # # pixmapitem.setPos(250, 70)

        # # Set all items as moveable and selectable.
        # for item in self.scene.items():
        #     item.setFlag(QGraphicsItem.ItemIsMovable)
        #     item.setFlag(QGraphicsItem.ItemIsSelectable)


class GetGraphInfoWorker(QObject):
    checkin = pyqtSignal()

    exit=False

    def run(self):
        while self.exit==False:
            self.checkin.emit()
            time.sleep(1)

    def quit(self):
        self.exit=True

