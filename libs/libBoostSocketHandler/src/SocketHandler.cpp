#include "SocketHandler.hpp"

#include <iostream>

#ifdef spdlog_FOUND
	#include "spdlog/spdlog.h"
#else 
	#define SPDLOG_TRACE(...) (void)0
	#define SPDLOG_DEBUG(...) (void)0
	#define SPDLOG_ERROR(...) (void)0
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
	SPDLOG_TRACE("initServer");

	tcp::acceptor acceptor_(m_ioService, tcp::endpoint(tcp::v4(), m_port));
	m_socketTcp=new tcp::socket(m_ioService);
	acceptor_.accept(*m_socketTcp);
}


bool Server::sendData(std::string& data)
{
	SPDLOG_TRACE("sendData");

	int nbBytes = data.size();
	sendSocketTcp(m_socketTcp, (char*)&nbBytes, sizeof(int), &m_error);

	if(m_error)
	{
		SPDLOG_ERROR("sendData failed: {0}", m_error.message());
		closeConnection();
		return false;
	}

	if(nbBytes!=0)
	{
		sendSocketTcp(m_socketTcp, (char*)&data[0], nbBytes, &m_error);

		if(m_error)
		{
			SPDLOG_ERROR("sendData failed: {0}", m_error.message());
			closeConnection();
			return false;
		}
	}

	return true;
}


bool Server::receive(std::string& data)
{
	SPDLOG_TRACE("receive");

	int nbBytes=0;
	readSocketTcp(m_socketTcp, (char*)&nbBytes, sizeof(int), &m_error);
	data.resize(nbBytes);

	if(m_error)
	{
		SPDLOG_ERROR("receive failed: {0}", m_error.message());
		closeConnection();
		return false;
	}

	if(nbBytes!=0)
	{
		readSocketTcp(m_socketTcp, &data[0], nbBytes, &m_error);

		if(m_error)
		{
			SPDLOG_ERROR("receive failed: {0}", m_error.message());
			closeConnection();
			return false;
		}
	}

	return true;
}


void Server::closeConnection()
{
	SPDLOG_TRACE("closeConnection");

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
	SPDLOG_TRACE("initConnection");

	boost::system::error_code error;
	m_socketTcp=new tcp::socket(m_ioService);
	m_socketTcp->connect( tcp::endpoint( boost::asio::ip::address::from_string(m_ipServer), m_port ), error);
	if(error)
		return false;

	return true;
}


bool Client::sendData(std::string& data)
{
	SPDLOG_TRACE("sendData");

	int nbBytes = data.size();
	sendSocketTcp(m_socketTcp, (char*)&nbBytes, sizeof(int), &m_error);

	if(m_error)
	{
		SPDLOG_ERROR("sendData failed: {0}", m_error.message());
		closeConnection();
		return false;
	}

	if(nbBytes!=0)
	{
		sendSocketTcp(m_socketTcp, (char*)&data[0], nbBytes, &m_error);

		if(m_error)
		{
			SPDLOG_ERROR("sendData failed: {0}", m_error.message());
			closeConnection();
			return false;
		}
	}

	return true;
}


bool Client::receive(std::string& data)
{
	SPDLOG_TRACE("receive");

	int nbBytes=0;
	readSocketTcp(m_socketTcp, (char*)&nbBytes, sizeof(int), &m_error);
	data.resize(nbBytes);

	if(m_error)
	{
		SPDLOG_ERROR("receive failed: {0}", m_error.message());
		closeConnection();
		return false;
	}

	if(nbBytes!=0)
	{
		readSocketTcp(m_socketTcp, &data[0], nbBytes, &m_error);

		if(m_error)
		{
			SPDLOG_ERROR("receive failed: {0}", m_error.message());
			closeConnection();
			return false;
		}
	}

	return true;
}


void Client::closeConnection()
{
	SPDLOG_TRACE("closeConnection");

	if(m_socketTcp)
	{
		delete m_socketTcp;
		m_socketTcp=nullptr;
	}
}


