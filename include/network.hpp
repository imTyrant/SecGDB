#ifndef SEC_GDB_H_NETWORK
#define SEC_GDB_H_NETWORK

#include <string>
#include <boost/asio.hpp>

namespace SecGDBNetwork
{
#ifdef SEC_GDB_ASYNC_NETWORK
    // Async code
    // Not implemented 
#else // SEC_GDB_ASYNC_NETWORK

using namespace boost::asio;

class NetServer
{
private:
    io_service& service;
    int native_socket; // Socket for Linux
    ip::tcp::acceptor acc;
public:
    NetServer(io_service& service, short port);
    ~NetServer();
    bool start();
    bool close();
};


#endif // SEC_GDB_ASYNC_NETWORK
};//SecGDBNetwork




#endif //SEC_GDB_H_NETWORK