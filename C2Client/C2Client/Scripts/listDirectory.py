import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__))+"/"+"..")

from grpcClient import *


def OnSessionStart(grpcClient, beaconHash, listenerHash, hostname, username, arch, privilege, os, lastProofOfLife, killed):
	output = "listDirectory:\n";	
	output += "load ListDirectory && ls\n";	

	commandLine = "loadModule ListDirectory"
	command = TeamServerApi_pb2.Command(beaconHash=beaconHash, listenerHash=listenerHash, cmd=commandLine)
	result = grpcClient.sendCmdToSession(command)
	
	commandLine = "ls"
	command = TeamServerApi_pb2.Command(beaconHash=beaconHash, listenerHash=listenerHash, cmd=commandLine)
	result = grpcClient.sendCmdToSession(command)

	return output
