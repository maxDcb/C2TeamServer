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
        server->initServer();

        string ret;
        bool res = server->receive(ret);
        if(res)
        {
            std::cout << "Server received - " << ret << std::endl;

            string out="Hello from server.";
            res = server->sendData(out);
            if(res)
            {
            }
            else
                std::cout << "Server send failed" << std::endl;
        }
        else
            std::cout << "Server receive failed" << std::endl;

        server->closeConnection();
    }
    
    delete server;

}