from ..grpcClient import TeamServerApi_pb2
from ..grpc_status import operation_ack_text


def OnStart(grpcClient):
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
