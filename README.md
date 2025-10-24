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
./TeamServer
```

---

### **🐳 Docker Deployment**

If you prefer containerized execution (recommended to avoid host library issues), build and run the Dockerfile:

```bash
# 0) Get Dockerfile
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

---

### **💻 Installing and Running the Client**

Install the Python client using [uv](https://docs.astral.sh/uv/getting-started/installation/):

```bash
# uv
uv tool install git+https://github.com/maxDcb/C2TeamServer.git#subdirectory=C2Client 
```

Set the path to the TeamServer certificate, if you run in a docker you can simply cp the `server.crt`, or if you follow the above section it should be in `/opt/C2TeamServer/TeamServer/server.crt`:

```bash
export C2_CERT_PATH=/path/to/teamserver/cert/server.crt
```

Connect to the TeamServer:

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

The **Exploration C2 Framework** consists of multiple components, including the **C2TeamServer**, **C2Implant**, and **C2LinuxImplant**. Below are the build instructions for **C2TeamServer**.

### 🔧 Build Process

1. **Install Dependencies**:

   * Ensure you have **CMake**, **g++**, and **Conan** installed.

    ```bash
    sudo apt install cmake
    pip3 install conan
    ```

2. **Clone the Repository**:
   If you haven't cloned the repository already, you can do so with:

   ```bash
   git clone https://github.com/maxDcb/C2TeamServer.git
   cd C2TeamServer
   git submodule update --init
   ```

3. **Configure the Build**:

   * Create a build directory and navigate into it.

   ```bash
   mkdir build
   cd build
   ```

   * Run CMake to configure the build process. This may take some time if you haven't installed the necessary dependencies yet, which are provided by Conan.

   ```bash
   cmake .. -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=./conan_provider.cmake
   ```

4. **Build the TeamServer**:

   * Now, you can compile the TeamServer with the following command:

   ```bash
   make
   ```

   * This will generate the `TeamServer` binary along with the TeamServer modules and copy them into the `Release` folder in the root directory of the project.
