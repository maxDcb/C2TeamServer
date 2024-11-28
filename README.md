# Exploration C2 Framework

<p align="center">
<img src="https://github.com/maxDcb/C2TeamServer/blob/master/images/Exploration1.png?raw=true" />
</p>

## What it is

Exploration is a redteam Command and Control framework.  
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


![alt text](https://github.com/maxDcb/C2TeamServer/blob/master/images/ListenersAndSessions2.png?raw=true)


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
pip3 install pycryptodome
pip3 install grpcio==1.66.1
pip3 install PyQt5
pip3 install pyqtdarktheme
pip3 install protobuf==5.27.0
```

```
cd  Release/Client 
# --dev is to specify that the GRPC hostname in the SSL certificat will not be checked
# --ip is the ip of the TeamServer
python3 GUI.py --ip 127.0.0.0 --port 50051 --dev
```

## Wiki

For more information, please visit the [wiki](https://github.com/maxDcb/C2TeamServer/wiki)
