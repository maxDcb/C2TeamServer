# Exploration C2 TeamServer

## What it is

Exploration is a rudimentary red team command and control frameworks.  
This repository contain the TeamServer and the GUI to communicate with the TeamServer.
This development is in education exercises to tackle well know red teaming concepts.

## Dependencies:

### Sumbodule & External Projects:  

* [Donut](https://github.com/TheWover/donut): Creat shellcode from PE files.  
* [cpp-httplib](https://github.com/yhirose/cpp-httplib): Http and Https Listener.  
* [CoffLoader](https://github.com/trustedsec/COFFLoader): Run object files from [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF).
* [MemoryModule](https://github.com/fancycode/MemoryModule): Load DLL at runtime.
* [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell): Powershell for unmanager code.
* [cpp-base64](https://github.com/ReneNyffenegger/cpp-base64): base64.
* [json](https://github.com/nlohmann/json): json parser.

### Compilation

#### Build the TeamServer

* apt install golang-cfssl (self sign cert for client server grpc communications)
* pip install conan (>=1.54)
* pip install grpcio
* pip install PyQt5
* pip install pyqtdarktheme
* pip install protobuf

git submodule update --init  
mkdir buildLinux  
cd buildLinux  
cmake ..   
make -j4  

The TeamServer binary is in Release/TeamServer  
it's launched using './TeamServer'  
The Python GUI is in Release/Client 
It's launched using 'python3 GUI.py'  

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/ReleaseTeamServerClient.png?raw=true)

#### Windows Beacon

Beacons and command modules are compiled separatly in an other [project](https://github.com/maxDcb/C2Implant), but the current version is provided in ./Release to be able to use it directly.

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/ReleaseModulesBeacons.png?raw=true)

Two side projects could be used to deliver the beacons:
* [PowershellWebDelivery](https://github.com/maxDcb/PowershellWebDelivery)
* [PeDropper](https://github.com/maxDcb/PeDropper)

## Command and Control

The Teamserver is a stand alone application which communicates with a client with GRPC channel (SSL). The Teamserver handle listeners.  
Implant run on the target host. Each implant or beacon which connect back to the TeamServer open a session. The session is used to control the implant, send commands and receive results.  
Listener and implant/beacon can run on TCP, HTTP and HTTPS   

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/ListenersAndSessions.png?raw=true)

Windows beacon uses primarily windows API and start with no module loaded. Module are loaded at runtime using "MemoryModule" project to load DLL sent by the server to the beacon.  

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/loadModule.png?raw=true)

Moreover the module AssemblyExec & Inject use Donut to give a lot of flexibility to the user, allowing him to launch whatever EXE or DLL he wants on the remote host.

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
| spawnAs          | 
| chisel           | 


TODO:  
- Donut only take 256 char for args, which is not enough for Rubeus.
- BeaconSmb.


