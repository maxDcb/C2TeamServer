#pragma once

#include <thread>
#include <string>
#include <iostream>


namespace PipeHandler
{

class Server
{
public:
	Server(const std::string& pipeName);
	~Server();

	bool initServer();

	bool sendData(std::string& data);
	bool receiveData(std::string& data);

private:
	bool reset();
	
	bool m_isInit;

	std::string m_pipeName;
};



class Client
{
public:
	Client(const std::string& ip, const std::string& pipeName);
	~Client();

	bool initConnection();
	bool closeConnection();	

	bool sendData(std::string& data);
	bool receiveData(std::string& data);

private:
	bool reset();
	
	bool m_isInit;

	std::string m_pipeName;
};

}
