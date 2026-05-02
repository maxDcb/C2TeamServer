import uuid

from ..grpcClient import TeamServerApi_pb2


def OnSessionStart(grpcClient, beaconHash, listenerHash, hostname, username, arch, privilege, os, lastProofOfLife, killed):
	output = ""
	if hostname == "sandboxhostname":
		output += "checkSandbox:\nSandbox detected ending beacon\n";

		commandLine = "end"
		command = TeamServerApi_pb2.SessionCommandRequest(
			session=TeamServerApi_pb2.SessionSelector(
				beacon_hash=beaconHash,
				listener_hash=listenerHash,
			),
			command=commandLine,
			command_id=uuid.uuid4().hex,
		)
		result = grpcClient.sendSessionCommand(command)
	
	return output
