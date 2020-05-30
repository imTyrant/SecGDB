#include <iostream>
#include <string>
#include "network.hpp"
#include <boost/asio.hpp>
#include <thread>

using namespace std;
using namespace boost::asio;
using boost::asio::ip::tcp;

SecGDBNetwork::NetServer::NetServer(io_service& service, short port)
    : service(service), acc(service, tcp::endpoint(tcp::v4(), port))
{
    this->native_socket = acc.native_handle();
}

SecGDBNetwork::NetServer::~NetServer()
{
    this->acc.close();
    this->native_socket = -1;
}

bool SecGDBNetwork::NetServer::start()
{
    std::thread()
}