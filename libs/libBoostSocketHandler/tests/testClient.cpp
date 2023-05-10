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
        std::cout << "InitConnection" << std::endl;

        while(!client->initConnection())
        {
            sleep(1);
        }
        std::cout << "Sending" << std::endl;

        string out="Hello";
        bool res = client->sendData(out);
        if(res)
        {
            std::cout << "Sent" << std::endl;
            std::cout << "Receiving" << std::endl;

            string ret;
            res = client->receive(ret);

            if(res)
            {
                std::cout << "Received" << std::endl;

                std::cout << "Client - " << ret << std::endl;
            }
            else
                std::cout << "Receive failed" << std::endl;
        }
        else
            std::cout << "Send failed" << std::endl;

        client->closeConnection();

        sleep(1);
    }

}