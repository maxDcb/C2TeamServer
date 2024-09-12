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
class Graph(QWidget):

    def __init__(self, parent, ip, port, devMode):
        super(QWidget, self).__init__(parent)

        width = self.frameGeometry().width()
        height = self.frameGeometry().height()

        print("width", width)
        print("height", height)

        self.ip = ip
        self.port = port
        self.grpcClient = GrpcClient(ip, port, devMode)

        self.scene = QGraphicsScene()

        for x in range(0,500,50): 
            self.scene.addLine(x, 0, x, 500)
        for y in range(0,500,50): 
            self.scene.addLine(0, y, 500, y)

        pixmap = QPixmap("firewall.png")
        pixmap = pixmap.scaled(64, 64)
        pixmapitem = self.scene.addPixmap(pixmap)
        pixmapitem.setPos(100, 50 );

        # pixmap = QPixmap("pc2.png")
        # pixmap = pixmap.scaled(64, 64)
        # pixmapitem = self.scene.addPixmap(pixmap)
        # pixmapitem.setPos(250, 70)

        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.Antialiasing)






        self.view._scene_rect = None
        self.view._scene_transform = None
        self.view._start_point = None

        self.view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.view.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.view.setRenderHint(QPainter.Antialiasing)
        self.view.setMouseTracking(True)
        self.view.setTransformationAnchor(self.view.NoAnchor)
        self.view.setResizeAnchor(self.view.NoAnchor)
        

        transform = QTransform()
        center = self.view.mapToScene(self.view.viewport().rect().center())
        transform.translate(center.x(), center.y())
        transform.scale(1 , 1 )
        transform.translate(-center.x(), -center.y())

        self.view.setTransform(transform)





        # Set all items as moveable and selectable.
        for item in self.scene.items():
            item.setFlag(QGraphicsItem.ItemIsMovable)
            item.setFlag(QGraphicsItem.ItemIsSelectable)

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


    def __del__(self):
        self.getGraphInfoWorker.quit()
        self.thread.quit()
        self.thread.wait()


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

