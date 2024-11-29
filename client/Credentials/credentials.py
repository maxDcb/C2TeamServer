import json
from grpcClient import GrpcClient

GetCredentialsInstruction = "getCred"
AddCredentialsInstruction = "addCred"

def addCredentials(grpcClient: GrpcClient,TeamServerApi_pb2, cred): 
    commandTeamServer = AddCredentialsInstruction
    termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=cred.encode())
    resultTermCommand = grpcClient.sendTermCmd(termCommand)
    print(resultTermCommand.result)


def getCredentials(grpcClient: GrpcClient,TeamServerApi_pb2): 
    addCredentials(grpcClient, TeamServerApi_pb2, '{"h": "b"}')
    commandTeamServer = GetCredentialsInstruction
    termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=b"")
    resultTermCommand = grpcClient.sendTermCmd(termCommand)
    result = resultTermCommand.result
    print(result)

