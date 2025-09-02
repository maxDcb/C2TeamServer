from ..grpcClient import TeamServerApi_pb2


def OnStart(grpcClient):
	output = "startListenerHttp8443:\nSend start listener https 8443\n";	

	listener = TeamServerApi_pb2.Listener(
            type="https",
            ip="0.0.0.0",
            port=8443)

	grpcClient.addListener(listener)

	return output

