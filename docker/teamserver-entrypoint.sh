#!/bin/sh
set -e

RELEASE_DIR="/opt/teamserver/Release"
TEAMSERVER_DIR="${RELEASE_DIR}/TeamServer"
TEAMSERVER_BIN="${TEAMSERVER_DIR}/TeamServer"

if [ ! -x "${TEAMSERVER_BIN}" ]; then
    cat >&2 <<'MSG'
[TeamServer] TeamServer binary was not found at /opt/teamserver/Release/TeamServer/TeamServer.
[TeamServer] Mount a populated Release directory into the container, for example:
[TeamServer]   docker run --rm --network host \
[TeamServer]     -v /path/to/Release:/opt/teamserver/Release \
[TeamServer]     exploration-teamserver:latest
MSG
    exit 1
fi

mkdir -p "${TEAMSERVER_DIR}/logs"

cd "${TEAMSERVER_DIR}"

exec "${TEAMSERVER_BIN}" "$@"
