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
    result = resultTermCommand.result
    return result


def handleSekurlsaLogonPasswords(mimikatzOutput: str, grpcClient: GrpcClient,TeamServerApi_pb2):
    auth_block_pattern = r"Authentication Id : .*?\n(.*?)(?=\nAuthentication Id :|\Z)"
    user_domain_pattern = r"User Name\s*:\s*(.*?)\s*Domain\s*:\s*(.*?)\n"
    ntlm_pattern = r"\*\s*NTLM\s*:\s*([a-fA-F0-9]{32})"
    password_pattern = r"\*\s*Password\s*:\s*(.+)"
    
    auth_blocks = re.findall(auth_block_pattern, mimikatzOutput, re.DOTALL)
    for block in auth_blocks:
        user_domain_match = re.search(user_domain_pattern, block)
        if user_domain_match:
            username = user_domain_match.group(1).strip()
            domain = user_domain_match.group(2).strip()
        else:
            username = "N/A"
            domain = "N/A"
        
        matchs = re.findall(ntlm_pattern, block)
        matchs = list(dict.fromkeys(matchs))
        for ntlm in matchs:
            ntlm = ntlm.strip()
            if ntlm:
                cred = {}
                cred["username"] = username
                cred["domain"] = domain
                cred["ntlm"] = ntlm
                addCredentials(grpcClient, TeamServerApi_pb2, json.dumps(cred))
        
        matchs = re.findall(password_pattern, block)
        matchs = list(dict.fromkeys(matchs))
        for password in matchs:
            password = password.strip()
            if password and password != "(null)":
                cred = {}
                cred["username"] = username
                cred["domain"] = domain
                cred["password"] = password
                addCredentials(grpcClient, TeamServerApi_pb2, json.dumps(cred))


def handleLsaDumpSAM(mimikatzOutput: str, grpcClient: GrpcClient,TeamServerApi_pb2):
    domain_block_pattern = r"(Domain :.*?)(?=\nDomain :|\Z)"
    domain_pattern = r"Domain : (.*)"
    rid_block_pattern = r"(RID\s*:.*?)(?=\nRID\s*:|\Z)"
    user_hash_pattern = r"User\s*:\s*(\S+)\r?\n\s+Hash NTLM:\s*([a-fA-F0-9]+)"

    domain_blocks = re.findall(domain_block_pattern, mimikatzOutput, re.DOTALL)
    for block in domain_blocks:
        domain_match = re.search(domain_pattern, block)
        if domain_match:
            domain = domain_match.group(1).strip()
        else:
            continue

        rid_blocks = re.findall(rid_block_pattern, block, re.DOTALL)
        for rid_block in rid_blocks:
            matches = re.findall(user_hash_pattern, rid_block)
            for user, hash_ntlm in matches:
                cred = {}
                cred["username"] = user
                cred["domain"] = domain
                cred["ntlm"] = hash_ntlm
                addCredentials(grpcClient, TeamServerApi_pb2, json.dumps(cred))


def handleMimikatzCredentials(mimikatzOutput: str, grpcClient: GrpcClient,TeamServerApi_pb2):
    # check if "sekurlsa::logonpasswords"
    handleSekurlsaLogonPasswords(mimikatzOutput, grpcClient,TeamServerApi_pb2)
    # check if "lsadump::sam"
    handleLsaDumpSAM(mimikatzOutput, grpcClient, TeamServerApi_pb2)
    # check if "sekurlsa::ekeys"
    # extract Password / aies256_hmac / rc4_md4
