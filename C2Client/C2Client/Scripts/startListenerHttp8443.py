from ..grpcClient import TeamServerApi_pb2
from ..grpc_status import operation_ack_text


DESCRIPTION = "Ensures the default HTTPS listener exists when the client connects."
HOOK_DESCRIPTIONS = {
	"OnStart": "Runs when the client connects or reconnects and asks the TeamServer to start HTTPS on 0.0.0.0:8443.",
}


def OnStart(grpcClient, context):
	output = "startListenerHttp8443:\nSend start listener https 8443\n";	

	listener = TeamServerApi_pb2.Listener(
            type="https",
            ip="0.0.0.0",
            port=8443)

	ack = grpcClient.addListener(listener)
	message = operation_ack_text(ack, "Listener command accepted.")
	if message:
		output += message + "\n"

	return output
