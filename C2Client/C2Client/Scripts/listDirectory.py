import uuid

from ..grpcClient import TeamServerApi_pb2
from ..grpc_status import is_response_ok, response_message


def OnSessionStart(grpcClient, beaconHash, listenerHash, hostname, username, arch, privilege, os, lastProofOfLife, killed):
	output = "listDirectory:\n";	
	output += "load ListDirectory\n";	

	commandLine = "loadModule ListDirectory"
	command = TeamServerApi_pb2.SessionCommandRequest(
		session=TeamServerApi_pb2.SessionSelector(
			beacon_hash=beaconHash,
			listener_hash=listenerHash,
		),
		command=commandLine,
		command_id=uuid.uuid4().hex,
	)
	result = grpcClient.sendSessionCommand(command)
	if not is_response_ok(result):
		output += response_message(result, "Command was rejected by TeamServer.") + "\n"
	
	# commandLine = "ls"
	# command = TeamServerApi_pb2.SessionCommandRequest(session=TeamServerApi_pb2.SessionSelector(beacon_hash=beaconHash, listener_hash=listenerHash), command=commandLine, command_id=uuid.uuid4().hex)
	# result = grpcClient.sendSessionCommand(command)

	return output
