import uuid

from ..grpcClient import TeamServerApi_pb2


def OnSessionStart(grpcClient, beaconHash, listenerHash, hostname, username, arch, privilege, os, lastProofOfLife, killed):
	output = "listDirectory:\n";	
	output += "load ListDirectory\n";	

	commandLine = "loadModule ListDirectory"
	command = TeamServerApi_pb2.Command(beaconHash=beaconHash, listenerHash=listenerHash, cmd=commandLine, commandId=uuid.uuid4().hex)
	result = grpcClient.sendCmdToSession(command)
	
	# commandLine = "ls"
	# command = TeamServerApi_pb2.Command(beaconHash=beaconHash, listenerHash=listenerHash, cmd=commandLine, commandId=uuid.uuid4().hex)
	# result = grpcClient.sendCmdToSession(command)

	return output
