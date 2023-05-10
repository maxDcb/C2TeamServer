#include "SocketHandler.hpp"

#include <iostream>


using namespace std;
using namespace SocketHandler;

int main()
{ 
    int port=4444;
    Server* server = new Server(port);

    while(1)
    {
        std::cout << "InitServer" << std::endl;

        // Wait a connection
        server->initServer();

        std::cout << "Receiving" << std::endl;

        string ret;
        bool res = server->receive(ret);
        if(res)
        {
            std::cout << "Received" << std::endl;

            std::cout << "Server - " << ret << std::endl;

            std::cout << "Sending" << std::endl;

            string out="{}";
            res = server->sendData(out);
            if(res)
            {
                std::cout << "Sent" << std::endl;
            }
            else
                std::cout << "send failed" << std::endl;
        }
        else
            std::cout << "Receive failed" << std::endl;
  
    }
    
    delete server;

}