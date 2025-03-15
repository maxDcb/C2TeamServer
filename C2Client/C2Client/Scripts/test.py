import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__))+"/"+"..")

from grpcClient import *


def OnStart(grpcClient):
	output = "Scrip test.py: OnStart\n";	

	listener = TeamServerApi_pb2.Listener(
            type="https",
            ip="0.0.0.0",
            port=8443)

	output += "addListener\n"
	grpcClient.addListener(listener)

	return output


def OnStop(grpcClient):
	output = "Scrip test.py: OnStop\n";	
	return output


def OnListenerStart(grpcClient):
	output = "Scrip test.py: OnListenerStart\n";	
	return output


def OnListenerStop(grpcClient):
	output = "Scrip test.py: OnListenerStop\n";	
	return output


def OnSessionStart(grpcClient, beaconHash, listenerHash, hostname, username, arch, privilege, os, lastProofOfLife, killed):
	output = "Scrip test.py: OnSessionStart\n";	
	output += "load ListDirectory && ls\n";	

	commandLine = "loadModule ListDirectory"
	command = TeamServerApi_pb2.Command(beaconHash=beaconHash, listenerHash=listenerHash, cmd=commandLine)
	result = grpcClient.sendCmdToSession(command)
	
	commandLine = "ls"
	command = TeamServerApi_pb2.Command(beaconHash=beaconHash, listenerHash=listenerHash, cmd=commandLine)
	result = grpcClient.sendCmdToSession(command)

	output += "Could imagine sending a mail or a slack notification...\n";

	return output


def OnSessionStop(grpcClient, beaconHash, listenerHash, hostname, username, arch, privilege, os, lastProofOfLife, killed):
	output = "Scrip test.py: OnSessionStop\n";	
	return output


def OnConsoleSend(grpcClient):
	output = "Scrip test.py: OnConsoleSend\n";	
	return output


def OnConsoleReceive(grpcClient):
	output = "Scrip test.py: OnConsoleReceive\n";	
	return output