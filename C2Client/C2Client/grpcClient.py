from __future__ import print_function

import logging

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/libGrpcMessages/build/py/')

import grpc
import TeamServerApi_pb2
import TeamServerApi_pb2_grpc
import pkg_resources


class GrpcClient:

    def __init__(self, ip, port, devMode):

        env_cert_path = os.getenv('CA_CERT_PATH')

        if env_cert_path and os.path.isfile(env_cert_path):
            ca_cert = env_cert_path
            print(f"Using CA certificate from environment variable: {ca_cert}")
        else:
            ca_cert = pkg_resources.resource_filename(
                'C2Client',  
                'server.crt' 
            )
            print(f"Using default CA certificate: {ca_cert}. To use a custom CA certificate, set the CA_CERT_PATH environment variable.")

        # ca_cert = './server.crt'
        root_certs = open(ca_cert, 'rb').read()

        credentials = grpc.ssl_channel_credentials(root_certs)
        if devMode:
            self.channel = grpc.secure_channel(ip + ':' + str(port), credentials, options=[('grpc.ssl_target_name_override', "localhost",), ('grpc.max_send_message_length', 512 * 1024 * 1024), ('grpc.max_receive_message_length', 512 * 1024 * 1024)])
        else:
            self.channel = grpc.secure_channel(ip + ':' + str(port), credentials, options=[('grpc.max_send_message_length', 512 * 1024 * 1024), ('grpc.max_receive_message_length', 512 * 1024 * 1024)])
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

    def sendTermCmd(self, command):
        response = self.stub.SendTermCmd(command)
        return response


