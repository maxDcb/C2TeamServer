import uuid

from ..grpcClient import TeamServerApi_pb2


def OnSessionStart(grpcClient, beaconHash, listenerHash, hostname, username, arch, privilege, os, lastProofOfLife, killed):
	output = ""
	if hostname == "sandboxhostname":
		output += "checkSandbox:\nSandbox detected ending beacon\n";

		commandLine = "end"
		command = TeamServerApi_pb2.Command(beaconHash=beaconHash, listenerHash=listenerHash, cmd=commandLine, commandId=uuid.uuid4().hex)
		result = grpcClient.sendCmdToSession(command)
	
	return output
