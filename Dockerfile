# syntax=docker/dockerfile:1
FROM ubuntu:24.04

LABEL org.opencontainers.image.title="Exploration TeamServer"
LABEL org.opencontainers.image.description="Container image for the Exploration C2 TeamServer."
LABEL org.opencontainers.image.source="https://github.com/maxDcb/C2TeamServer"

ENV TEAMSERVER_HOME=/opt/teamserver
WORKDIR ${TEAMSERVER_HOME}

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY Release/ ${TEAMSERVER_HOME}/Release/
COPY docker/teamserver-entrypoint.sh /usr/local/bin/teamserver-entrypoint.sh

RUN chmod +x /usr/local/bin/teamserver-entrypoint.sh \
    && if [ -f "${TEAMSERVER_HOME}/Release/TeamServer/TeamServer" ]; then \
        chmod +x "${TEAMSERVER_HOME}/Release/TeamServer/TeamServer"; \
    fi

VOLUME ["/opt/teamserver/Release"]

EXPOSE 50051 80 443 445

ENTRYPOINT ["/usr/local/bin/teamserver-entrypoint.sh"]
