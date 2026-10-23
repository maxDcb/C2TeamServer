"""Minimal V2 job client with an explicit, durable event cursor."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import sys
import time
import uuid

import grpc

from .grpcClient import GrpcClient


def _record(job: object) -> dict[str, object]:
    return {
        "job_id": job.job_id,
        "operation": job.operation,
        "state": job.state,
        "created_at": job.created_at,
        "queued_at": job.queued_at,
        "completed_at": job.completed_at,
        "error_code": job.error_code,
        "error_message": job.error_message,
        "output_size": job.output_size,
        "output_base64": base64.b64encode(job.output_inline).decode("ascii"),
    }


def _save_cursor(path: Path, cursor: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="ascii") as stream:
        stream.write(f"{cursor}\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Submit and follow durable TeamServer jobs")
    parser.add_argument("--ip", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=50051)
    parser.add_argument("--dev", action="store_true", help="Use localhost as the TLS server name")
    commands = parser.add_subparsers(dest="action", required=True)

    submit = commands.add_parser("submit")
    submit.add_argument("operation")
    submit.add_argument("input", help="Echo bytes as text, or a session command line")
    submit.add_argument("--job-id", default="")
    submit.add_argument("--beacon-hash", default="")
    submit.add_argument("--listener-hash", default="")

    get = commands.add_parser("get")
    get.add_argument("job_id")

    listing = commands.add_parser("list")
    listing.add_argument("--after-created-at", type=int, default=0)
    listing.add_argument("--after-job-id", default="")
    listing.add_argument("--page-size", type=int, default=100)

    watch = commands.add_parser("watch")
    watch.add_argument("--after-event-id", type=int)
    watch.add_argument("--cursor-file", type=Path)
    watch.add_argument("--job-id", default="")
    watch.add_argument("--state", default="")
    watch.add_argument("--once", action="store_true")
    watch.add_argument("--max-events", type=int, default=0)

    options = parser.parse_args(argv)
    try:
        client = GrpcClient(options.ip, options.port, options.dev)
        if options.action == "submit":
            if options.operation == "session_command":
                if not options.beacon_hash or not options.listener_hash:
                    parser.error("session_command requires --beacon-hash and --listener-hash")
                job_input = json.dumps({
                    "beacon_hash": options.beacon_hash,
                    "listener_hash": options.listener_hash,
                    "command": options.input,
                }, separators=(",", ":"))
            else:
                job_input = options.input
            job = client.submitJob(options.job_id or uuid.uuid4().hex, options.operation, job_input)
            print(json.dumps(_record(job), sort_keys=True))
            return 0
        if options.action == "get":
            print(json.dumps(_record(client.getJobExecution(options.job_id)), sort_keys=True))
            return 0
        if options.action == "list":
            page = client.listJobExecutions(options.after_created_at, options.after_job_id, options.page_size)
            print(json.dumps({
                "jobs": [_record(job) for job in page.jobs],
                "next_created_at": page.next_created_at,
                "next_job_id": page.next_job_id,
            }, sort_keys=True))
            return 0

        cursor = options.after_event_id
        if cursor is None:
            cursor = int(options.cursor_file.read_text().strip()) if options.cursor_file and options.cursor_file.exists() else 0
        if cursor < 0:
            parser.error("Event cursor cannot be negative")
        delivered = 0
        while True:
            try:
                for event in client.subscribeJobEvents(
                    after_event_id=cursor, job_id=options.job_id,
                    state=options.state, follow=not options.once):
                    if event.event_id <= cursor:
                        continue
                    print(json.dumps({
                        "event_id": event.event_id,
                        "job_id": event.job_id,
                        "event_type": event.event_type,
                        "created_at": event.created_at,
                        "payload_json": event.payload_json,
                    }, sort_keys=True), flush=True)
                    cursor = event.event_id
                    if options.cursor_file:
                        _save_cursor(options.cursor_file, cursor)
                    delivered += 1
                    if options.max_events and delivered >= options.max_events:
                        return 0
                if options.once:
                    return 0
            except grpc.RpcError as error:
                print(f"Event stream disconnected: {error}", file=sys.stderr)
                time.sleep(1)
    except (OSError, ValueError, grpc.RpcError) as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
