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
	return true;
}


bool Server::sendData(std::string& data)
{
	return true;
}


bool Server::receiveData(std::string& data)
{
	return true;
}


// https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-client
Client::Client(const std::string& pipeName)
{

}


Client::~Client()
{

}


bool Client::initConnection()
{
	return true;
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
	return true;
}


bool Client::receiveData(std::string& data)
{
	return true;
}


