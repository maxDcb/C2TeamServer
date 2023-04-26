#include "SocketHandler.hpp"

#include <iostream>


using namespace std;
using namespace SocketHandler;

int main()
{
    int remotePort=4444;
	string remoteHost="127.0.0.1";

    Client* client=new Client(remoteHost, remotePort);

    while(1)
    {
        string out="Hello";
        client->sendData(out);

        string ret;
        client->receive(ret);

        std::cout << "Client - " << ret << std::endl;

#ifdef __linux__
        sleep(1);
#elif _WIN32
        Sleep(1);
#endif
    }

}