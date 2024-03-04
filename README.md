# Exploration C2 TeamServer

## What it is

Exploration is a rudimentary red team command and control framework.  
This repository contains the Team Server and the GUI to communicate with the Team Server.
This development is an educational exercise to tackle well know red teaming concepts.

## Dependencies:

### Sumbodule & External Projects:  

* [Donut](https://github.com/TheWover/donut): Creat shellcode from PE files.  
* [cpp-httplib](https://github.com/yhirose/cpp-httplib): Http and Https Listener.  
* [CoffLoader](https://github.com/trustedsec/COFFLoader): Run object files from [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF).
* [MemoryModule](https://github.com/fancycode/MemoryModule): Load DLL at runtime.
* [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell): Powershell for unmanaged code.
* [cpp-base64](https://github.com/ReneNyffenegger/cpp-base64): base64.
* [json](https://github.com/nlohmann/json): json parser.

### Compilation

#### Build the TeamServer

```
sudo apt install gcc-mingw-w64
sudo apt install g++-mingw-w64
pip3 install pycryptodome

sudo apt install golang-cfssl
sudo apt install cmake 

pip install conan
pip install grpcio
pip install PyQt5
pip install pyqtdarktheme
pip install protobuf

export PATH=$PATH:/home/kali/.local/bin/
conan profile detect

sudo updatedb

git clone https://github.com/maxDcb/C2TeamServer.git
cd C2TeamServer
git submodule update --init
mkdir buildLinux
cd buildLinux
cmake ..
make -j4
```

The TeamServer binary is in Release/TeamServer  
it's launched using './TeamServer'  
The Python GUI is in Release/Client 
It's launched using 'python3 GUI.py'  

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/ReleaseTeamServerClient.png?raw=true)

#### Windows Beacon

Beacons and command modules are compiled separately in another [project](https://github.com/maxDcb/C2Implant), but the current version is provided in ./Release to be able to use it directly.

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/ReleaseModulesBeacons.png?raw=true)

Two side projects can be used to deliver the beacons:
* [PowershellWebDelivery](https://github.com/maxDcb/PowershellWebDelivery)
* [PeDropper](https://github.com/maxDcb/PeDropper)

## Command and Control

The Team Server is a stand alone application which communicates with a client with GRPC channel (SSL). The Teamserver handle listeners.  
Implant run on the target host. Each implant or beacon which connects back to the Team Server open a session. The session is used to control the implant, send commands and receive results.  
A listener and implant/beacon can run on TCP, SMB, HTTP and HTTPS 

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/ListenersAndSessions.png?raw=true)

Windows beacon uses primarily windows API and start with no module loaded. Modules are loaded at runtime using "MemoryModule" project to load DLL sent by the server to the beacon.  

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/loadModule.png?raw=true)

Moreover, the module AssemblyExec & Inject use Donut to give a lot of flexibility to the user, allowing him to launch whatever EXE or DLL he wants on the remote host.

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/AssemblyExecMimikatz.png?raw=true)

Coff Module is used to run Coff files.  

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/coffDir.png?raw=true)


## Modules List

| Module           |
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




