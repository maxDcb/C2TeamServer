import sys
import os
import time
from threading import Thread, Lock
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtGui import QPixmap, QTransform

from grpcClient import *


#
# Constant
#
BeaconNodeItemType = "Beacon"
ListenerNodeItemType = "Listener"

PrimaryListenerImage = "images/firewall.svg"
WindowsSessionImage = "images/pc.svg"
LinuxSessionImage = "images/linux.svg"


#
# Graph Tab Implementation
#
# needed to send the message of mouseMoveEvent because QGraphicsPixmapItem doesn't herit from QObject
class Signaller(QObject):
    signal = pyqtSignal()

    def trigger(self):
        self.signal.emit()


class NodeItem(QGraphicsPixmapItem):
    # Signal to notify position changes
    signaller = Signaller()

    def __init__(self, type, hash, os="",  privilege="", parent=None):
        if type == ListenerNodeItemType:
            self.type = ListenerNodeItemType
            pixmap = QPixmap(PrimaryListenerImage).scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.beaconHash = ""
            self.connectedListenerHash = ""
            self.listenerHash = []
            self.listenerHash.append(hash)
        elif type == BeaconNodeItemType:
            self.type = BeaconNodeItemType
            # print("NodeItem beaconHash", hash, "os", os, "privilege", privilege)
            if "linux" in os.lower():
                pixmap = QPixmap(LinuxSessionImage).scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            elif "windows" in os.lower():
                pixmap = QPixmap(WindowsSessionImage).scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            else:
                pixmap = QPixmap(LinuxSessionImage).scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.beaconHash=hash
            self.connectedListenerHash = ""
            self.listenerHash=[]

        super().__init__(pixmap)

    def print(self):
        print("NodeItem", self.type, "beaconHash", self.beaconHash, "listenerHash", self.listenerHash, "connectedListenerHash", self.connectedListenerHash)

    def isResponsableForListener(self, hash):
        if hash in self.listenerHash:
            return True      
        else:
            return False

    def mouseMoveEvent(self, event):
        super().mouseMoveEvent(event)
        self.signaller.trigger() 

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        self.setCursor(Qt.ClosedHandCursor)

    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
        self.setCursor(Qt.ArrowCursor)
        

class Connector(QGraphicsLineItem):

    def __init__(self, listener, beacon, pen=None):
        super().__init__()
        self.listener = listener
        self.beacon = beacon

        self.pen = pen or QPen(QColor("white"), 3)
        self.setPen(self.pen)
        self.update_line()

    def print(self):
        print("Connector", "beaconHash", self.beacon.beaconHash, "connectedListenerHash", self.beacon.connectedListenerHash, "listenerHash", self.listener.listenerHash)

    def update_line(self):
        # print("listener", self.listener.pos())
        # print("beacon", self.beacon.pos())
        center1 = self.listener.pos() + self.listener.boundingRect().center()
        center2 = self.beacon.pos() + self.beacon.boundingRect().center()
        self.setLine(QLineF(center1, center2))
        
        
class Graph(QWidget):
    listNodeItem = []
    listNodeItem = []
    listConnector = []

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

        self.thread = QThread()
        self.getGraphInfoWorker = GetGraphInfoWorker()
        self.getGraphInfoWorker.moveToThread(self.thread)
        self.thread.started.connect(self.getGraphInfoWorker.run)
        self.getGraphInfoWorker.checkin.connect(self.updateGraph)
        self.thread.start()

        # self.updateScene()
        

    def __del__(self):
        self.getGraphInfoWorker.quit()
        self.thread.quit()
        self.thread.wait()

 
    def updateConnectors(self):
        for connector in self.listConnector:
            connector.update_line()


    # Update the graphe every X sec with information from the team server
    def updateGraph(self):

        #
        # Update beacons
        #
        responses = self.grpcClient.getSessions()
        sessions = list()
        for response in responses:
            sessions.append(response)

        # delete beacon
        for ix, nodeItem in enumerate(self.listNodeItem):
            runing=False
            for session in sessions:
                if session.beaconHash == nodeItem.beaconHash:
                    runing=True
            if not runing and self.listNodeItem[ix].type == BeaconNodeItemType:
                for ix2, connector in enumerate(self.listConnector):
                    if connector.beacon.beaconHash == nodeItem.beaconHash:
                        print("[-] delete connector")
                        self.scene.removeItem(self.listConnector[ix2])
                        del self.listConnector[ix2]
                print("[-] delete beacon", nodeItem.beaconHash)
                self.scene.removeItem(self.listNodeItem[ix])
                del self.listNodeItem[ix]

        # add beacon
        for session in sessions:
            inStore=False
            for ix, nodeItem in enumerate(self.listNodeItem):
                if session.beaconHash == nodeItem.beaconHash:
                    inStore=True
            if not inStore:
                item = NodeItem(BeaconNodeItemType, session.beaconHash, session.os, session.privilege)
                item.connectedListenerHash = session.listenerHash
                item.signaller.signal.connect(self.updateConnectors)
                self.scene.addItem(item)
                self.listNodeItem.append(item)
                print("[+] add beacon", session.beaconHash)

        #
        # Update listener
        #
        responses= self.grpcClient.getListeners()
        listeners = list()
        for listener in responses:
            listeners.append(listener)

        # delete listener
        for ix, nodeItem in enumerate(self.listNodeItem):
            runing=False
            for listener in listeners:
                if nodeItem.isResponsableForListener(listener.listenerHash):
                    runing=True
            if not runing:
                # primary listener
                if self.listNodeItem[ix].type == ListenerNodeItemType:
                    for ix2, connector in enumerate(self.listConnector):
                        if self.listNodeItem[ix2].listenerHash in connector.listener.listenerHash:
                            print("[-] delete connector")
                            self.scene.removeItem(self.listConnector[ix2])
                            del self.listConnector[ix2]
                    print("[-] delete primary listener", nodeItem.listenerHash)
                    self.scene.removeItem(self.listNodeItem[ix])
                    del self.listNodeItem[ix]
                    
                # beacon listener
                elif self.listNodeItem[ix].type == BeaconNodeItemType:
                    if listener.listenerHash in self.listNodeItem[ix].listenerHash:
                        for ix2, connector in enumerate(self.listConnector):
                            if self.listNodeItem[ix2].listenerHash in connector.listener.listenerHash:
                                print("[-] delete connector")
                                self.scene.removeItem(self.listConnector[ix2])
                                del self.listConnector[ix2]
                        print("[-] delete secondary listener", nodeItem.listenerHash)
                        self.listNodeItem[ix].listenerHash.remove(listener.listenerHash)

        # add listener
        for listener in listeners:
            inStore=False
            for ix, nodeItem in enumerate(self.listNodeItem):
                if nodeItem.isResponsableForListener(listener.listenerHash):
                    inStore=True
            if not inStore:
                if not listener.beaconHash:
                    item = NodeItem(ListenerNodeItemType, listener.listenerHash)
                    item.signaller.signal.connect(self.updateConnectors)
                    self.scene.addItem(item)
                    self.listNodeItem.append(item)
                    print("[+] add primary listener", listener.listenerHash)
                else:
                    for nodeItem2 in self.listNodeItem:
                        if nodeItem2.beaconHash == listener.beaconHash:
                            nodeItem2.listenerHash.append(listener.listenerHash)
                            print("[+] add secondary listener", listener.listenerHash)

        #
        # Update connectors
        #        
        for nodeItem in self.listNodeItem:
            if nodeItem.type == BeaconNodeItemType:
                inStore=False
                beaconHash = nodeItem.beaconHash
                listenerHash = nodeItem.connectedListenerHash
                for connector in self.listConnector:
                    if connector.listener.isResponsableForListener(listenerHash) and connector.beacon.beaconHash == beaconHash:
                        inStore=True
                if not inStore:
                    for listener in self.listNodeItem:
                        if listener.isResponsableForListener(listenerHash)==True:
                            connector = Connector(listener, nodeItem)
                            self.scene.addItem(connector)
                            connector.setZValue(-1)
                            self.listConnector.append(connector)
                            print("[+] add connector listener:", listenerHash, "beacon", beaconHash)

        for item in self.listNodeItem:
            item.setFlag(QGraphicsItem.ItemIsMovable)
            item.setFlag(QGraphicsItem.ItemIsSelectable)

        
class GetGraphInfoWorker(QObject):
    checkin = pyqtSignal()

    exit=False

    def run(self):
        while self.exit==False:
            self.checkin.emit()
            time.sleep(5)

    def quit(self):
        self.exit=True

