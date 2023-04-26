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
        string out="Man";
        server->sendData(out);

        string ret;
        server->receive(ret);

        std::cout << "Server - " << ret << std::endl;

#ifdef __linux__
        sleep(1);
#elif _WIN32
        Sleep(1);
#endif
        
    }

}