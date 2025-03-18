from __future__ import print_function

import logging

import sys
import os
import uuid
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/libGrpcMessages/build/py/')

import grpc
import TeamServerApi_pb2
import TeamServerApi_pb2_grpc


class GrpcClient:

    def __init__(self, ip, port, devMode):

        env_cert_path = os.getenv('C2_CERT_PATH')

        if env_cert_path and os.path.isfile(env_cert_path):
            ca_cert = env_cert_path
            print(f"Using certificate from environment variable: {ca_cert}")
        else:
            try:
                import pkg_resources
                ca_cert = pkg_resources.resource_filename(
                    'C2Client',  
                    'server.crt' 
                )
            except ImportError:
                ca_cert = os.path.join(os.path.dirname(__file__), 'server.crt')
            print(f"Using default certificate: {ca_cert}. To use a custom C2 certificate, set the C2_CERT_PATH environment variable.")

        if os.path.exists(ca_cert):
            root_certs = open(ca_cert, 'rb').read()
        else:
            print(f"[-] Error: {ca_cert} not found, this file is needed to secure the communication beetween the client and server.")
            print(f"You can find it in the release directory of the Teamserver.")
            print(f"Exiting.")
            raise ValueError("grpcClient: Certificate not found")

        credentials = grpc.ssl_channel_credentials(root_certs)
        if devMode:
            self.channel = grpc.secure_channel(ip + ':' + str(port), credentials, options=[('grpc.ssl_target_name_override', "localhost",), ('grpc.max_send_message_length', 512 * 1024 * 1024), ('grpc.max_receive_message_length', 512 * 1024 * 1024)])
        else:
            self.channel = grpc.secure_channel(ip + ':' + str(port), credentials, options=[('grpc.max_send_message_length', 512 * 1024 * 1024), ('grpc.max_receive_message_length', 512 * 1024 * 1024)])
        grpc.channel_ready_future(self.channel).result()
        self.stub = TeamServerApi_pb2_grpc.TeamServerApiStub(self.channel)

        self.metadata = [
            ("authorization", "Bearer my-secret-token"),
            ("clientid", str(uuid.uuid4())[:16])
        ]

    def getListeners(self):
        empty = TeamServerApi_pb2.Empty()
        listeners = self.stub.GetListeners(empty, metadata=self.metadata)
        return listeners

    def addListener(self, listener):
        response = self.stub.AddListener(listener, metadata=self.metadata)
        return response

    def stopListener(self, listener):
        response = self.stub.StopListener(listener, metadata=self.metadata)
        return response

    def getSessions(self):
        empty = TeamServerApi_pb2.Empty()
        sessions = self.stub.GetSessions(empty, metadata=self.metadata)
        return sessions

    def stopSession(self, session):
        response = self.stub.StopSession(session, metadata=self.metadata)
        return response

    def sendCmdToSession(self, command):
        response = self.stub.SendCmdToSession(command, metadata=self.metadata)
        return response

    def getResponseFromSession(self, session):
        commands = self.stub.GetResponseFromSession(session, metadata=self.metadata)
        return commands

    def getHelp(self, command):
        response = self.stub.GetHelp(command, metadata=self.metadata)
        return response

    def sendTermCmd(self, command):
        response = self.stub.SendTermCmd(command, metadata=self.metadata)
        return response


