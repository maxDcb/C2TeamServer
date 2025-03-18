import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__))+"/"+"..")

from grpcClient import *


def OnStart(grpcClient):
	output = "startListenerHttp8443:\nSend start listener https 8443\n";	

	listener = TeamServerApi_pb2.Listener(
            type="https",
            ip="0.0.0.0",
            port=8443)

	grpcClient.addListener(listener)

	return output

