import uuid

from ..grpcClient import TeamServerApi_pb2
from ..grpc_status import is_response_ok, response_message

MODULES = ["ls", "cd", "pwd", "tree"]

def ManualStart(grpcClient, context):
    output = []

    for session in context["sessions"]:
        if session["killed"]:
            continue

        selector = TeamServerApi_pb2.SessionSelector(
            beacon_hash=session["beacon_hash"],
            listener_hash=session["listener_hash"],
        )

        for module in MODULES:
            command_line = f"loadModule {module}"
            command = TeamServerApi_pb2.SessionCommandRequest(
                session=selector,
                command=command_line,
                command_id=uuid.uuid4().hex,
            )
            ack = grpcClient.sendSessionCommand(command)
            if is_response_ok(ack):
                output.append(f'{session["hostname"]}: queued {command_line}')
            else:
                output.append(
                    f'{session["hostname"]}: failed {command_line}: '
                    + response_message(ack, "Command rejected.")
                )

    return "\n".join(output)