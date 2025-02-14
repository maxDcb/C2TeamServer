# Exploration C2 Framework

<p align="center">
<img src="https://github.com/maxDcb/C2TeamServer/blob/master/images/Exploration1.png?raw=true" />
</p>

## What it is

Exploration is a red team Command and Control (C2) framework.  
This repository includes both the TeamServer and the Client.  
The release package contains the TeamServer, the Client, as well as the beacons and modules for Windows from [C2Implant](https://github.com/maxDcb/C2Implant) and for Linux from [C2Implant](https://github.com/maxDcb/C2LinuxImplant).


You can run the following command to retrieve the latest release:
```
wget -q $(wget -q -O - 'https://api.github.com/repos/maxDcb/C2TeamServer/releases/latest' | jq -r '.assets[] | select(.name=="Release.tar.gz").browser_download_url') -O ./C2TeamServer.tar.gz
mkdir C2TeamServer && tar xf C2TeamServer.tar.gz -C C2TeamServer --strip-components 1
```

## Introduction

The TeamServer is a standalone application, coded in C++, that handles listeners. The Client, coded in Python, communicates with the TeamServer through gRPC.  
Beacons run on the victim host. Each Beacon that connects back to the TeamServer opens a new session. This session is used to control the Beacon, send commands, and receive results.  
Listeners and Beacons can communicate through TCP, SMB, HTTP, HTTPS.  


![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/ListenersAndSessions.png?raw=true)


![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/ListenersAndSessions2.png?raw=true)


A compiled version of the TeamServer is available in the Releases, complete with default certificates for gRPC communication and HTTP Listener.

The TeamServer binary is in Release/TeamServer. It can be launched using the following command:

```
./TeamServer
```

![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/TeamServerLaunch.png?raw=true)

The Python Client is located in Release/Client. It can be launched using the following command:

```
cd  Release/Client 
# --dev is to specify that the GRPC hostname in the SSL certificat will not be checked
# --ip is the ip of the TeamServer
python3 GUI.py --ip 127.0.0.0 --port 50051 --dev
```

## Wiki

For more information, please visit the [wiki](https://github.com/maxDcb/C2TeamServer/wiki)
