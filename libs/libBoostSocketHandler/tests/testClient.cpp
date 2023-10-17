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
        while(!client->initConnection())
        {
            sleep(1);
        }

        string out="Hello from the client.";
        bool res = client->sendData(out);
        if(res)
        {
            string ret;
            res = client->receive(ret);

            if(res)
            {
                std::cout << "Client received - " << ret << std::endl;
            }
            else
                std::cout << "Client receive failed" << std::endl;
        }
        else
            std::cout << "Client send failed" << std::endl;

        client->closeConnection();

        sleep(1);
    }

}