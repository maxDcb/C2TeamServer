# Exploration C2 Framework

<p align="center">
  <img src="images/Exploration1.png?raw=true" alt="Exploration C2 Logo" />
</p>

## Overview

**Exploration** is a modular Command and Control framework for red team operations.

This repository contains:

- C++ TeamServer
- Python Client
- Release packaging for Windows assets from [C2Implant](https://github.com/maxDcb/C2Implant)
- Release packaging for Linux assets from [C2LinuxImplant](https://github.com/maxDcb/C2LinuxImplant)

## Look And Feel

<p align="center">
  <img src="images/ListenersAndSessions.png?raw=true" />
</p>

<p align="center">
  <img src="images/ListenersAndSessions2.png?raw=true" />
</p>

## Architecture

The TeamServer manages listeners and sessions. The Python Client talks to the TeamServer through gRPC.

Supported listener channels:

- `TCP`
- `SMB`
- `HTTP`
- `HTTPS`

<p align="center">
  <img src="images/architecture.png" />
</p>

## Repository Layout

```text
protocol/     .proto source and generated gRPC build rules
teamServer/   TeamServer runtime and gRPC implementation
C2Client/     Python client package and UI
core/         shared C++ components
packaging/    release bundle assembly and validation
integration/  runtime staging and integration tests
docs/         build, release, CI/CD, and integration notes
```

## Quick Start

Download the latest release:

```bash
wget -q $(wget -q -O - 'https://api.github.com/repos/maxDcb/C2TeamServer/releases/latest' | jq -r '.assets[] | select(.name=="Release.tar.gz").browser_download_url') -O ./C2TeamServer.tar.gz
mkdir C2TeamServer
tar xf C2TeamServer.tar.gz -C C2TeamServer --strip-components 1
```

Start the TeamServer:

```bash
cd C2TeamServer/TeamServer
./TeamServer
```

Install and run the client:

```bash
cd C2TeamServer/Client
python -m venv .venv
. .venv/bin/activate
pip install .

export C2_CERT_PATH="$PWD/../TeamServer/server.crt"
c2client --ip 127.0.0.1 --port 50051
```

## Docker

```bash
docker build -t exploration-teamserver .
docker run --rm -it \
  --name exploration-teamserver \
  -p 50051:50051 \
  -p 80:80 \
  -p 443:443 \
  -p 8443:8443 \
  exploration-teamserver
```

Use a local release bundle:

```bash
docker run --rm -it \
  -v "$PWD/Release:/opt/teamserver/Release:ro" \
  -p 50051:50051 \
  exploration-teamserver
```

## Build And Release Docs

- [Build and tests](docs/build.md)
- [Release packaging](docs/release.md)
- [Implant asset contract](docs/implants.md)
- [CI/CD contract](docs/ci-cd.md)
- [Integration runtime](docs/integration.md)

## Blog Series

[Building a Modern C2](https://maxdcb.github.io/BuildingAModernC2/)

- Part 0: Setup and basic usage
- Part 1: TeamServer and architecture
- Part 2: GUI and operator workflows
- Part 3: Beacons and listeners
- Part 4: Modules
