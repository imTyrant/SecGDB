#ifndef SEC_GDB_H_NETWORK
#define SEC_GDB_H_NETWORK

#include <string>
#include <boost/asio.hpp>
#include <gmpxx.h>

int net_recv_sized_data(boost::asio::ip::tcp::socket& sock, char* &buff);
bool net_send_sized_data(boost::asio::ip::tcp::socket& sock, int size, char* buff);

bool net_recv_mpz_class(boost::asio::ip::tcp::socket& sock, mpz_class& out);
bool net_send_mpz_class(boost::asio::ip::tcp::socket& sock, mpz_class& in);

#endif //SEC_GDB_H_NETWORK