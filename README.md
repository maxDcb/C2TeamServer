# Exploration C2 Framework

Exploration is a modular command-and-control framework intended for authorized
red-team operations. This repository contains the C++ TeamServer, the Python/Qt
operator client, shared gRPC contracts, modules, and deterministic release tooling.

## 1.0.0-rc.1 security model

The release archive contains no credential, private key, vault key, or bootstrap
password. A TeamServer instance owns all mutable state outside the release tree.
Every gRPC call uses TLS and authentication; roles are `viewer`, `operator`, and
`admin`. Production can require client certificates.

## First run

Extract `Release.tar.gz`, then initialize and run a local standalone instance:

```bash
cd Release/TeamServer
./TeamServer init \
  --profile standalone \
  --instance-dir "$HOME/.local/share/exploration-teamserver" \
  --hostname localhost \
  --listen-address 127.0.0.1
./TeamServer run --instance-dir "$HOME/.local/share/exploration-teamserver"
```

The initialization command prints the paths of:

- the public client profile;
- the one-time bootstrap credential file;
- the TLS certificate fingerprint.

In another terminal:

```bash
cd Release/Client
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export C2_USERNAME=admin
export C2_PASSWORD='value from instance/secrets/bootstrap.txt'
./run-client.sh --profile "$HOME/.local/share/exploration-teamserver/client/client-profile.json"
```

Delete `bootstrap.txt` after moving the password into your secret manager.

## Production

Production initialization is fail-closed and requires an external certificate and
private key. mTLS is strongly recommended:

```bash
C2_BOOTSTRAP_PASSWORD_FILE=/run/secrets/bootstrap-password ./TeamServer init \
  --profile production \
  --instance-dir /var/lib/teamserver \
  --hostname teamserver.example.internal \
  --listen-address 0.0.0.0 \
  --tls-cert /run/secrets/server.crt \
  --tls-key /run/secrets/server.key \
  --trust-cert /run/secrets/operator-trust.crt \
  --client-ca /run/secrets/operator-ca.crt \
  --require-client-cert
```

See [SECURITY.md](SECURITY.md) and the release's `TeamServer/README-FIRST-RUN.md`.

## Docker

Container builds require the checksum published beside the immutable RC archive:

```bash
docker build \
  --build-arg C2TEAMSERVER_SHA256="$(cut -d' ' -f1 Release.tar.gz.sha256)" \
  -t exploration-teamserver:1.0.0-rc.1 .
docker run --rm -p 50051:50051 \
  -v exploration-teamserver-data:/var/lib/teamserver \
  exploration-teamserver:1.0.0-rc.1
```

The container runs as UID/GID `10001`; its instance state lives only in the mounted
volume.

## Build and release documentation

- [Build and tests](docs/build.md)
- [Release packaging](docs/release.md)
- [Implant asset contract](docs/implants.md)
- [CI/CD contract](docs/ci-cd.md)
- [Integration runtime](docs/integration.md)
