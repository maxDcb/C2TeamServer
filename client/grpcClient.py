from __future__ import print_function

import logging

import sys
sys.path.insert(1, './libGrpcMessages/build/py/')

import grpc
import TeamServerApi_pb2
import TeamServerApi_pb2_grpc


class GrpcClient:

    def __init__(self, ip, port):

        ca_cert = './rootCA.crt'
        root_certs = open(ca_cert, 'rb').read()

        credentials = grpc.ssl_channel_credentials(root_certs)
        self.channel = grpc.secure_channel(ip + ':' + str(port), credentials)
        grpc.channel_ready_future(self.channel).result()
        self.stub = TeamServerApi_pb2_grpc.TeamServerApiStub(self.channel)

    def getListeners(self):
        empty = TeamServerApi_pb2.Empty()
        listeners = self.stub.GetListeners(empty)
        return listeners

    def addListener(self, listener):
        response = self.stub.AddListener(listener)
        return response

    def stopListener(self, listener):
        response = self.stub.StopListener(listener)
        return response

    def getSessions(self):
        empty = TeamServerApi_pb2.Empty()
        sessions = self.stub.GetSessions(empty)
        return sessions

    def stopSession(self, session):
        response = self.stub.StopSession(session)
        return response

    def sendCmdToSession(self, command):
        response = self.stub.SendCmdToSession(command)
        return response

    def getResponseFromSession(self, session):
        commands = self.stub.GetResponseFromSession(session)
        return commands

    def getHelp(self, command):
        response = self.stub.GetHelp(command)
        return response


