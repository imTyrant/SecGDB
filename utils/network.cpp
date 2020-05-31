#include <iostream>
#include <string>
#include <gmpxx.h>
#include <boost/asio.hpp>

#include "network.hpp"
#include "crypto_stuff.hpp"
#include "ggm.h"

using namespace std;
using namespace boost::asio;
using boost::asio::ip::tcp;


int net_recv_sized_data(tcp::socket& sock, char* &buff)
{
    int size = 0;
    boost::system::error_code ec;
    boost::asio::read(sock, boost::asio::buffer(reinterpret_cast<char*>(&size), sizeof(size)), ec);
    if (ec || size == 0) { buff = nullptr; return 0; }
    buff = new char[size];
    boost::asio::read(sock, boost::asio::buffer(buff, size), ec);
    if (ec) { delete buff; buff == nullptr; return 0; }
    return size;
}

bool net_send_sized_data(tcp::socket& sock, int size, char* buff)
{
    char* char_size = reinterpret_cast<char*>(size);
    boost::system::error_code ec;
    boost::asio::write(sock, boost::asio::buffer(char_size, sizeof(int)), ec);
    if (ec) { return false; }
    boost::asio::write(sock, boost::asio::buffer(buff, size), ec);
    if (ec) { return false; }
    return true;
}

bool net_recv_mpz_class(tcp::socket& sock, mpz_class& out)
{
    char* buff = nullptr;
    int size = net_recv_sized_data(sock, buff);
    if (size == 0) {return false;}
    set_mpz_raw(out.get_mpz_t(), size, buff);
    delete buff;
    return true;
}

bool net_send_mpz_class(tcp::socket& sock, mpz_class& in)
{
    string container = let_mpz_raw_to_str(in.get_mpz_t());
    return net_send_sized_data(sock, container.size(), (char*)container.c_str());
}


bool net_recv_constrain(tcp::socket& sock, GGM& ggm, Constrain& con)
{
    Constrain* tmp = &con;
    int con_size = 0;
    boost::system::error_code ec;
    boost::asio::read(sock, boost::asio::buffer(reinterpret_cast<char*>(&con_size), sizeof(con_size)), ec);
    if (ec) { return false; }
    if (con_size < 1) { return false; }
    for (int i = 0; i < con_size - 1; i ++) // For the last one
    {
        int key_size = net_recv_sized_data(sock, tmp->key);
        tmp->next = new Constrain({0});
        tmp = tmp->next;
    }
    int key_size = net_recv_sized_data(sock, tmp->key);
    tmp->next = nullptr;
    return true;
}

bool net_send_constrain(tcp::socket& sock, GGM& ggm, Constrain& con)
{
    int con_size = 0;
    Constrain* tmp = &con;
    while (tmp)
    {
        con_size ++;
        tmp = tmp->next;
    }
    boost::system::error_code ec;
    boost::asio::write(sock, boost::asio::buffer((char*)&con_size, sizeof(int)), ec);
    if (ec) { return false; }
    tmp = &con;
    while(tmp)
    {
        if (!net_send_sized_data(sock, ggm.key_size, tmp->key))
        {
            return false;
        }
        tmp = tmp->next;
    }
}