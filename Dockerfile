# syntax=docker/dockerfile:1
FROM ubuntu:24.04

LABEL org.opencontainers.image.title="Exploration TeamServer"
LABEL org.opencontainers.image.description="Container image for the Exploration C2 TeamServer."
LABEL org.opencontainers.image.source="https://github.com/maxDcb/C2TeamServer"

ENV TEAMSERVER_HOME=/opt/teamserver
WORKDIR ${TEAMSERVER_HOME}
ARG C2TEAMSERVER_RELEASE_URL=""

# Install minimal dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libstdc++6 \
        wget \
        jq \
        tar \
    && rm -rf /var/lib/apt/lists/*

# Download and extract the latest Release from GitHub, or use an explicit URL.
RUN set -eux; \
    if [ -n "${C2TEAMSERVER_RELEASE_URL}" ]; then \
        release_url="${C2TEAMSERVER_RELEASE_URL}"; \
    else \
        release_url="$(wget -q -O - "https://api.github.com/repos/maxDcb/C2TeamServer/releases/latest" \
            | jq -r '.assets[] | select(.name=="Release.tar.gz").browser_download_url')"; \
    fi; \
    wget -q "${release_url}" -O /tmp/Release.tar.gz; \
    mkdir -p "${TEAMSERVER_HOME}/Release"; \
    tar xf /tmp/Release.tar.gz --strip-components=1 -C "${TEAMSERVER_HOME}/Release"; \
    rm /tmp/Release.tar.gz

# Add the entrypoint script directly
RUN cat > /usr/local/bin/teamserver-entrypoint.sh <<'EOF'
#!/bin/sh
set -e

RELEASE_DIR="/opt/teamserver/Release"
TEAMSERVER_DIR="${RELEASE_DIR}/TeamServer"
TEAMSERVER_BIN="${TEAMSERVER_DIR}/TeamServer"

if [ ! -x "${TEAMSERVER_BIN}" ]; then
    cat >&2 <<'MSG'
[TeamServer] TeamServer binary was not found at /opt/teamserver/Release/TeamServer/TeamServer.
[TeamServer] The image normally ships with a bundled Release directory.
[TeamServer] If you want to override it, mount your own bundle on /opt/teamserver/Release.
MSG
    exit 1
fi

mkdir -p "${TEAMSERVER_DIR}/logs"

cd "${TEAMSERVER_DIR}"

exec "${TEAMSERVER_BIN}" "$@"
EOF

# Make entrypoint executable + binary (if present)
RUN chmod +x /usr/local/bin/teamserver-entrypoint.sh \
    && if [ -f "${TEAMSERVER_HOME}/Release/TeamServer/TeamServer" ]; then \
        chmod +x "${TEAMSERVER_HOME}/Release/TeamServer/TeamServer"; \
    fi

EXPOSE 50051 80 443 8443

ENTRYPOINT ["/usr/local/bin/teamserver-entrypoint.sh"]
