# syntax=docker/dockerfile:1.7
FROM ubuntu:24.04

LABEL org.opencontainers.image.title="Exploration TeamServer" \
      org.opencontainers.image.version="1.0.0-rc.1" \
      org.opencontainers.image.source="https://github.com/maxDcb/C2TeamServer"

ARG C2TEAMSERVER_VERSION="1.0.0-rc.1"
ARG C2TEAMSERVER_RELEASE_URL="https://github.com/maxDcb/C2TeamServer/releases/download/1.0.0-rc.1/Release.tar.gz"
ARG C2TEAMSERVER_SHA256

ENV TEAMSERVER_RELEASE_DIR=/opt/teamserver/Release \
    C2_INSTANCE_DIR=/var/lib/teamserver

RUN test -n "$C2TEAMSERVER_SHA256" \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libstdc++6 \
    && curl --fail --location --proto '=https' --tlsv1.2 \
        "$C2TEAMSERVER_RELEASE_URL" -o /tmp/Release.tar.gz \
    && echo "$C2TEAMSERVER_SHA256  /tmp/Release.tar.gz" | sha256sum --check --strict \
    && mkdir -p "$TEAMSERVER_RELEASE_DIR" \
    && tar --extract --gzip --file /tmp/Release.tar.gz --strip-components=1 \
        --directory "$TEAMSERVER_RELEASE_DIR" \
    && test -x "$TEAMSERVER_RELEASE_DIR/TeamServer/TeamServer" \
    && groupadd --gid 10001 teamserver \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /var/lib/teamserver \
        --shell /usr/sbin/nologin teamserver \
    && mkdir -p "$C2_INSTANCE_DIR" \
    && chown teamserver:teamserver "$C2_INSTANCE_DIR" \
    && rm -f /tmp/Release.tar.gz \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 docker/teamserver-entrypoint.sh /usr/local/bin/teamserver-entrypoint

USER 10001:10001
WORKDIR /opt/teamserver/Release/TeamServer
VOLUME ["/var/lib/teamserver"]
EXPOSE 50051

ENTRYPOINT ["/usr/local/bin/teamserver-entrypoint"]
