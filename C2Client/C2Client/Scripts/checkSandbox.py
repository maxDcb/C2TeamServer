import uuid

from ..grpcClient import TeamServerApi_pb2
from ..grpc_status import is_response_ok, response_message


DESCRIPTION = "Stops new beacon sessions that look like the known sandbox hostname."
HOOK_DESCRIPTIONS = {
	"OnSessionStart": "Checks the session object from the trigger snapshot and queues end when the hostname is sandboxhostname.",
}


def OnSessionStart(grpcClient, context):
	output = ""
	session = context.get("object") or context.get("event", {})
	beaconHash = session.get("beacon_hash", "")
	listenerHash = session.get("listener_hash", "")
	hostname = session.get("hostname", "")
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
		if not is_response_ok(result):
			output += response_message(result, "Command was rejected by TeamServer.") + "\n"
	
	return output
