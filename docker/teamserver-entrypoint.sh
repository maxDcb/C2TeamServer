#!/bin/sh
set -eu

TEAMSERVER_BIN="${TEAMSERVER_RELEASE_DIR:-/opt/teamserver/Release}/TeamServer/TeamServer"
INSTANCE_DIR="${C2_INSTANCE_DIR:-/var/lib/teamserver}"

if [ ! -x "$TEAMSERVER_BIN" ]; then
    echo "TeamServer binary not found: $TEAMSERVER_BIN" >&2
    exit 1
fi

if [ "$#" -gt 0 ]; then
    exec "$TEAMSERVER_BIN" "$@"
fi

if [ ! -f "$INSTANCE_DIR/config/TeamServerConfig.json" ]; then
    "$TEAMSERVER_BIN" init \
        --profile standalone \
        --instance-dir "$INSTANCE_DIR" \
        --hostname "${C2_HOSTNAME:-localhost}" \
        --listen-address 0.0.0.0 \
        --port "${C2_PORT:-50051}"
fi

exec "$TEAMSERVER_BIN" run --instance-dir "$INSTANCE_DIR"
