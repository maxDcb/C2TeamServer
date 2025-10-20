# Exploration C2 Framework

<p align="center">
  <img src="images/Exploration1.png?raw=true" alt="Exploration C2 Logo" />
</p>

## Overview

**Exploration** is a modular and extensible Command and Control (C2) framework designed for red team operations.  
This repository includes both the **TeamServer** (backend) and the **Client** (frontend).  

The latest release package contains:
- The C++ **TeamServer**
- The Python **Client**
- Windows modules and beacons from [C2Implant](https://github.com/maxDcb/C2Implant)
- Linux modules and beacons from [C2LinuxImplant](https://github.com/maxDcb/C2LinuxImplant)

## Look and Feel

<p align="center">
  <img src="images/ListenersAndSessions.png?raw=true" />
</p>


<p align="center">
  <img src="images/ListenersAndSessions2.png?raw=true" />
</p>

## Architecture

The **TeamServer** is a standalone C++ application that manages listeners and active sessions.  
The **Client**, written in Python, interacts with the TeamServer via gRPC.

Beacons deployed on target machines initiate callbacks to the TeamServer, opening interactive sessions. These sessions can be used to send commands, receive output, and control implants.  
Supported communication channels for listeners and beacons include: `TCP`, `SMB`, `HTTP`, and `HTTPS`.

## Architecture Diagrams

<p align="center">
  <img src="images/architecture.png" />
</p>

## Quick Start

### Running the TeamServer

A precompiled version of the TeamServer is available in the release archive. It includes default TLS certificates for gRPC and HTTP communication.

To download the latest release, use the following command, or directly from the [release page](https://github.com/maxDcb/C2TeamServer/releases):

```bash
wget -q $(wget -q -O - 'https://api.github.com/repos/maxDcb/C2TeamServer/releases/latest' | jq -r '.assets[] | select(.name=="Release.tar.gz").browser_download_url') -O ./C2TeamServer.tar.gz \
&& mkdir C2TeamServer && tar xf C2TeamServer.tar.gz -C C2TeamServer --strip-components 1
```

To launch the TeamServer:

```bash
cd Release
./TeamServer
```

<p align="center">
  <img src="images/TeamServerLaunch.png?raw=true" />
</p>

### Docker Deployment

If you prefer containerized execution (recommended to avoid host library issues), build and run the Dockerfile.

```bash
# 0) Get docker file
curl -sL https://raw.githubusercontent.com/maxDcb/C2TeamServer/refs/heads/master/Dockerfile -o Dockerfile

# 1) Build
sudo docker build -t exploration-teamserver .

# 2) Create a host copy of the release
CID=$(sudo docker create exploration-teamserver)
sudo docker cp "$CID":/opt/teamserver/Release /opt/C2TeamServer
sudo docker rm "$CID"

# 3) Run container with host Release mounted (for easy editing)
sudo docker run -it --rm --name exploration-teamserver -v /opt/C2TeamServer/Release:/opt/teamserver/Release -p 50051:50051 -p 80:80 -p 443:443 -p 8443:8443 exploration-teamserver
```  

   > ℹ️ The container runtime is based on **Ubuntu 24.04**, which provides glibc 2.39 and libstdc++ 13. These versions satisfy the runtime requirements of the precompiled TeamServer binary. Running the server on older base images (e.g., Debian 12/bookworm) will result in errors such as `GLIBC_2.38 not found` or `GLIBCXX_3.4.32 not found`.

### Installing and Running the Client

Install the Python client using your favorit Python environment / package management tools:

```bash
# pipx
pipx install git+https://github.com/maxDcb/C2TeamServer.git#subdirectory=C2Client

# uv
uv tool install git+https://github.com/maxDcb/C2TeamServer.git#subdirectory=C2Client 
```

Set the path to the TeamServer certificate:

```bash
export C2_CERT_PATH=/path/to/teamserver/cert/server.crt
```

Connect to the TeamServer:

```bash
c2client --ip 127.0.0.1 --port 50051 --dev
```

> ⚠️ `--dev` disables hostname verification in the gRPC TLS certificate (for development/testing purposes).

Or in local:

```bash
cd ./C2Client
uv sync
export C2_CERT_PATH=/path/to/teamserver/cert/server.crt
uv run python -m C2Client.GUI
```

## Documentation

For detailed usage, configuration, and module documentation, refer to the [Wiki](https://github.com/maxDcb/C2TeamServer/wiki).
