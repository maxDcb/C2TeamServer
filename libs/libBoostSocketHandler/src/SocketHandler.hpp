#pragma once

#include <fstream>
#include <memory>
#include <chrono>
#include <random>
#include <vector>
#include <thread>

#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <boost/shared_ptr.hpp>

namespace SocketHandler
{

class Server
{
public:
	Server(int port);
	~Server();

	void initServer();

	bool sendData(std::string& data);
	bool receive(std::string& data);

private:
	void reset();
	
	void creatServerTcp(int port);

	bool m_initDone;
	int m_port;

	boost::asio::io_service m_ioService;
	boost::asio::ip::tcp::socket* m_socketTcp;
	boost::system::error_code m_error;
};



class Client
{
public:
	Client(std::string& ip, int port);
	~Client();

	bool initConnection();
	void closeConnection();

	bool sendData(std::string& data);
	bool receive(std::string& data);

private:
	bool reset();
	bool creatClientTcp(int port, std::string& ip);

	std::string m_ipServer;
	int m_port;

	boost::asio::io_service m_ioService;
	boost::asio::ip::tcp::socket* m_socketTcp;
	boost::system::error_code m_error;
};

}


