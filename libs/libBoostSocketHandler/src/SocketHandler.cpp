#include "SocketHandler.hpp"

#include <iostream>

#define DEBUG_BUILD

#ifdef DEBUG_BUILD
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define DEBUG(x) do { std::cout << __FILENAME__ << " - " << __func__ << ": " << x << std::endl; } while (0)
#else
#define DEBUG(x) do {} while (0)
#endif

using boost::asio::ip::tcp;
using namespace SocketHandler;


void sendSocketTcp(boost::asio::ip::tcp::socket* socket_, char* data, int nbBytes, boost::system::error_code* err)
{
	boost::asio::const_buffers_1 buff(data, nbBytes);
	boost::asio::write(*socket_, buff, *err);
}


void readSocketTcp(boost::asio::ip::tcp::socket* socket_, char* data, int nbBytes, boost::system::error_code* err)
{
	boost::asio::mutable_buffers_1 buff(data, nbBytes);
	boost::asio::read(*socket_, buff, boost::asio::transfer_all(), *err);
}


Server::Server(int port)
{
	m_port = port;
}


Server::~Server()
{
	delete m_socketTcp;
}


void Server::initServer()
{
	DEBUG("initServer");

	tcp::acceptor acceptor_(m_ioService, tcp::endpoint(tcp::v4(), m_port));
	m_socketTcp=new tcp::socket(m_ioService);
	acceptor_.accept(*m_socketTcp);
}


bool Server::sendData(std::string& data)
{
	DEBUG("sendData");

	int nbBytes = data.size();
	sendSocketTcp(m_socketTcp, (char*)&nbBytes, sizeof(int), &m_error);

	if(m_error)
	{
		DEBUG("sendData failed: " << m_error.message());
		closeConnection();
		return false;
	}

	if(nbBytes!=0)
	{
		sendSocketTcp(m_socketTcp, (char*)&data[0], nbBytes, &m_error);

		if(m_error)
		{
			DEBUG("sendData failed: " << m_error.message());
			closeConnection();
			return false;
		}
	}

	return true;
}


bool Server::receive(std::string& data)
{
	DEBUG("receive");

	int nbBytes=0;
	readSocketTcp(m_socketTcp, (char*)&nbBytes, sizeof(int), &m_error);
	data.resize(nbBytes);

	if(m_error)
	{
		DEBUG("receive failed: " << m_error.message());
		closeConnection();
		return false;
	}

	if(nbBytes!=0)
	{
		readSocketTcp(m_socketTcp, &data[0], nbBytes, &m_error);

		if(m_error)
		{
			DEBUG("receive failed: " << m_error.message());
			closeConnection();
			return false;
		}
	}

	return true;
}


void Server::closeConnection()
{
	DEBUG("closeConnection");

	if(m_socketTcp)
	{
		delete m_socketTcp;
		m_socketTcp=nullptr;
	}
}


Client::Client(std::string& ip, int port)
{
	m_ipServer = ip;
	m_port = port;
}


Client::~Client()
{
	if(m_socketTcp)
	{
		delete m_socketTcp;
		m_socketTcp=nullptr;
	}
}


bool Client::initConnection()
{
	DEBUG("initConnection");

	boost::system::error_code error;
	m_socketTcp=new tcp::socket(m_ioService);
	m_socketTcp->connect( tcp::endpoint( boost::asio::ip::address::from_string(m_ipServer), m_port ), error);
	if(error)
		return false;

	return true;
}


bool Client::sendData(std::string& data)
{
	DEBUG("sendData");

	int nbBytes = data.size();
	sendSocketTcp(m_socketTcp, (char*)&nbBytes, sizeof(int), &m_error);

	if(m_error)
	{
		DEBUG("sendData failed: " << m_error.message());
		closeConnection();
		return false;
	}

	if(nbBytes!=0)
	{
		sendSocketTcp(m_socketTcp, (char*)&data[0], nbBytes, &m_error);

		if(m_error)
		{
			DEBUG("sendData failed: " << m_error.message());
			closeConnection();
			return false;
		}
	}

	return true;
}


bool Client::receive(std::string& data)
{
	DEBUG("receive");

	int nbBytes=0;
	readSocketTcp(m_socketTcp, (char*)&nbBytes, sizeof(int), &m_error);
	data.resize(nbBytes);

	if(m_error)
	{
		DEBUG("receive failed: " << m_error.message());
		closeConnection();
		return false;
	}

	if(nbBytes!=0)
	{
		readSocketTcp(m_socketTcp, &data[0], nbBytes, &m_error);

		if(m_error)
		{
			DEBUG("receive failed: " << m_error.message());
			closeConnection();
			return false;
		}
	}

	return true;
}


void Client::closeConnection()
{
	DEBUG("closeConnection");

	if(m_socketTcp)
	{
		delete m_socketTcp;
		m_socketTcp=nullptr;
	}
}


