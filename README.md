# **Exploration C2 Framework 🚀**

<p align="center">
  <img src="images/Exploration1.png?raw=true" alt="Exploration C2 Logo" />
</p>

## **📋 Overview**

**Exploration** is a modular and extensible Command and Control (C2) framework tailored for red team operations. This repository contains the backend **TeamServer** (written in C++) and the frontend **Client** (written in Python).

The latest release package includes:

* The C++ **TeamServer**
* The Python **Client**
* Windows modules and beacons from [C2Implant](https://github.com/maxDcb/C2Implant)
* Linux modules and beacons from [C2LinuxImplant](https://github.com/maxDcb/C2LinuxImplant)

---

## **👀 Look and Feel**

<p align="center">
  <img src="images/ListenersAndSessions.png?raw=true" />
</p>

<p align="center">
  <img src="images/ListenersAndSessions2.png?raw=true" />
</p>

---

## **🏗️ Architecture**

The **TeamServer** is a standalone C++ application responsible for managing listeners and active sessions.
The **Client**, written in Python, communicates with the TeamServer through gRPC.

Beacons deployed on target machines initiate callbacks to the TeamServer, establishing interactive sessions. These sessions are used to send commands, receive output, and control implants.
Supported communication channels include: `TCP`, `SMB`, `HTTP`, and `HTTPS`.

### **🖥️ Architecture Diagram**

<p align="center">
  <img src="images/architecture.png" />
</p>

---

## **⚡ Quick Start**

### **🖥️ Running the TeamServer**

A precompiled version of the TeamServer is available in the release archive, which includes default TLS certificates for gRPC and HTTP communication.

To download the latest release, use the following command, or visit the [release page](https://github.com/maxDcb/C2TeamServer/releases):

```bash
wget -q $(wget -q -O - 'https://api.github.com/repos/maxDcb/C2TeamServer/releases/latest' | jq -r '.assets[] | select(.name=="Release.tar.gz").browser_download_url') -O ./C2TeamServer.tar.gz \
&& mkdir C2TeamServer && tar xf C2TeamServer.tar.gz -C C2TeamServer --strip-components 1
```

To launch the TeamServer:

```bash
cd Release
cd TeamServer
./TeamServer
```

---

### **🐳 Docker Deployment**

If you prefer containerized execution, the repository `Dockerfile` now runs the packaged TeamServer bundle directly:

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

The image downloads the latest `Release.tar.gz` during the image build and starts `/opt/teamserver/Release/TeamServer/TeamServer`.
If you want to override the packaged bundle with a local one, mount your own `Release` directory on `/opt/teamserver/Release`.

---

### **💻 Installing and Running the Client**

Install the Python client from the staged release bundle or from the repository sources.

If you use a staged release bundle, set the path to the TeamServer certificate:

```bash
export C2_CERT_PATH=/path/to/Release/TeamServer/server.crt
```

Then connect to the TeamServer:

```bash
c2client --ip 127.0.0.1 --port 50051 
```

---

## **📝 Building a Modern C2 — Blog Series**

Explore an in-depth, hands-on guide to developing a modern Command and Control (C2) framework. This series covers the architecture, design decisions, and implementation details of the **C2TeamServer** project.

🔗 [Read the full series here](https://maxdcb.github.io/BuildingAModernC2/)

---

### **📚 Series Overview**

* **Part 0 — Setup and Basic Usage**: Learn how to set up and launch your first Linux beacon.
* **Part 1 — TeamServer & Architecture**: Discover the build system, messaging choices, and listener management.
* **Part 2 — GUI & Operator Workflows**: Dive into the design goals and functionalities of the graphical user interface.
* **Part 3 — Beacons & Listeners**: Understand implant architecture and channel implementations.
* **Part 4 — Modules**: Explore module templates and implementation strategies.

---

The added emojis help bring some fun and engagement to the titles and sections, guiding the reader through the document while also visually highlighting the key parts.

## 🛠️ Build

The repository now uses:

- `Conan` for C/C++ dependencies
- `CMake` for configuration
- `GNU Make` or another CMake generator for compilation
- `pyproject.toml` and `requirements.txt` for Python dependencies

### 🔧 Build From Scratch

Validated commands in WSL/Linux:

```bash
git clone https://github.com/maxDcb/C2TeamServer.git
cd C2TeamServer
git submodule update --init --recursive

python3 -m pip install --upgrade "conan==2.24.0"

cmake -B build -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=$PWD/conan_provider.cmake
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

Notes:

- Use the absolute path to `conan_provider.cmake`. The old relative example was not reliable.
- Build artifacts are generated in the build tree, not written back into the repository root.
- The validated build currently runs `53` CTest tests from the root build.

### 🧪 Client Tests

The client depends on the generated Python protocol package produced by the root CMake build:

```bash
cd C2Client
python -m venv .venv
. .venv/bin/activate
pip install -e .[test]

export C2_PROTOCOL_PYTHON_ROOT=$PWD/../build/generated/python_protocol
pytest tests -q
```

### 📦 Stage A Release Bundle

To assemble the local release bundle from build outputs:

```bash
cmake --build build --target stage_release_bundle
```

The bundle is created under:

```text
build/release-staging/Release
```

This staged bundle contains:

- `TeamServer`
- `TeamServerModules`
- the generated Python client protocol package
- the Python client sources and launchers
