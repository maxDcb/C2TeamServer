#include "PipeHandler.hpp"


using namespace PipeHandler;


// https://learn.microsoft.com/en-us/windows/win32/ipc/multithreaded-pipe-server
Server::Server(const std::string& pipeName)
{
	m_pipeName="\\\\.\\pipe\\";
	m_pipeName+=pipeName;
}


Server::~Server()
{
}


bool Server::reset()
{
	return true;
}


bool Server::initServer()
{
	return false;
}

bool Server::openServer() { return false; }
bool Server::acceptConnection() { return false; }
void Server::stop() {}

bool Server::sendData(std::string& data)
{
	return false;
}


bool Server::receiveData(std::string& data)
{
	return false;
}
void Server::waitForClientClose() {}


// https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-client
Client::Client(const std::string& ip, const std::string& pipeName)
{

}


Client::~Client()
{

}


bool Client::initConnection()
{
	return false;
}


bool Client::closeConnection()
{
	return true;
}


bool Client::reset()
{	
	return true;
}


bool Client::sendData(std::string& data)
{ 
	return false;
}


bool Client::receiveData(std::string& data)
{
	return false;
}


