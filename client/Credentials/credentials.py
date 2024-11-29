import json
from grpcClient import GrpcClient
import re

GetCredentialsInstruction = "getCred"
AddCredentialsInstruction = "addCred"

def getCredentials(grpcClient: GrpcClient, TeamServerApi_pb2): 
    commandTeamServer = GetCredentialsInstruction
    termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=b"")
    resultTermCommand = grpcClient.sendTermCmd(termCommand)
    result = resultTermCommand.result
    return result


def addCredentials(grpcClient: GrpcClient,TeamServerApi_pb2, cred: str): 
    currentcredentials = json.loads(getCredentials(grpcClient, TeamServerApi_pb2))
    credjson = json.loads(cred)

    if credjson in currentcredentials:
        return

    commandTeamServer = AddCredentialsInstruction
    termCommand = TeamServerApi_pb2.TermCommand(cmd=commandTeamServer, data=cred.encode())
    resultTermCommand = grpcClient.sendTermCmd(termCommand)
    print(resultTermCommand.result)


def handleSekurlsaLogonPasswords(mimikatzOutput: str, grpcClient: GrpcClient,TeamServerApi_pb2):
    auth_block_pattern = r"Authentication Id : .*?\n(.*?)(?=\nAuthentication Id :|\Z)"  # Each block of data
    user_domain_pattern = r"User Name\s*:\s*(.*?)\s*Domain\s*:\s*(.*?)\n"  # Username and Domain
    ntlm_pattern = r"msv\s*:\s*.*?NTLM\s*:\s*([a-fA-F0-9]+)"  # msv section
    auth_blocks = re.findall(auth_block_pattern, mimikatzOutput, re.DOTALL)
    for block in auth_blocks:
        # Extract Username and Domain
        user_domain_match = re.search(user_domain_pattern, block)
        if user_domain_match:
            username = user_domain_match.group(1).strip()
            domain = user_domain_match.group(2).strip()
        else:
            username = "N/A"
            domain = "N/A"
        
        # Extract msv section
        ntlm_match = re.search(ntlm_pattern, block, re.DOTALL)
        ntlm = ntlm_match.group(1).strip() if ntlm_match else ""
        if ntlm != "":
            cred = {}
            cred["username"] = username
            cred["domain"] = domain
            cred["ntlm"] = ntlm
            addCredentials(grpcClient, TeamServerApi_pb2, json.dumps(cred))
        
        # Print results
        print(getCredentials(grpcClient, TeamServerApi_pb2))




def handleMimikatzCredentials(mimikatzOutput: str, grpcClient: GrpcClient,TeamServerApi_pb2):
    handleSekurlsaLogonPasswords(mimikatzOutput, grpcClient,TeamServerApi_pb2)

