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
    int rcv_size = 0;
    boost::system::error_code ec;
    rcv_size = boost::asio::read(sock, boost::asio::buffer(reinterpret_cast<char*>(&size), sizeof(size)), ec);
    if (ec || size == 0 || rcv_size == 0) { buff = nullptr; throw sec_gdb_network_exception("Reading data size failed!", ec.value()); }
    buff = new char[size];
    rcv_size = boost::asio::read(sock, boost::asio::buffer(buff, size), ec);
    if (ec || rcv_size == 0) { delete buff; buff == nullptr; throw sec_gdb_network_exception("Reading data failed!", ec.value()); }
    return size;
}

bool net_send_sized_data(tcp::socket& sock, int size, char* buff)
{
    int bytes_num = size;
    boost::system::error_code ec;
    boost::asio::write(sock, boost::asio::buffer(reinterpret_cast<char*>(&bytes_num), sizeof(bytes_num)), ec);
    if (ec) { throw sec_gdb_network_exception("Writing data size failed!", ec.value()); }
    boost::asio::write(sock, boost::asio::buffer(buff, size), ec);
    if (ec) { throw sec_gdb_network_exception("Writing data failed!", ec.value()); }
    return true;
}

bool net_recv_mpz_class(tcp::socket& sock, mpz_class& out)
{
    try
    {
        char* buff = nullptr;
        int size = net_recv_sized_data(sock, buff);
        set_mpz_raw(out.get_mpz_t(), size, buff);
        delete buff;
    }
    catch (const sec_gdb_network_exception& e)
    {
        std::cerr << "Error message: " << e.get_msg() << " Error code: " << e.get_ec() << endl;
        throw sec_gdb_network_exception("Receiving mpz_class occurs error!", e.get_ec()); 
    }
    catch (...)
    {   
        throw sec_gdb_network_exception("Unknown error occurs during receiving mpz_class!", -1);
    }
    
    return true;
}

bool net_send_mpz_class(tcp::socket& sock, mpz_class& in)
{
    try
    {
        string container = let_mpz_raw_to_str(in.get_mpz_t());
        net_send_sized_data(sock, container.size(), (char*)container.c_str());
    }
    catch (const sec_gdb_network_exception& e)
    {
        std::cerr << "Error message: " << e.get_msg() << " Error code: " << e.get_ec() << endl;
        throw sec_gdb_network_exception("Sending mpz_class occurs error!", e.get_ec()); 
    }
    catch(...)
    {
        throw sec_gdb_network_exception("Unknown error occurs during sending mpz_class!", -1);
    }
    return true;
}

bool net_recv_constrain(tcp::socket& sock, GGM& ggm, Constrain& con, int& ctr)
{
    Constrain* tmp = &con;
    int con_size = 0;
    boost::system::error_code ec;
    boost::asio::read(sock, boost::asio::buffer(reinterpret_cast<char*>(&ctr), sizeof(ctr)), ec);
    if (ec) { throw sec_gdb_network_exception("Receiving counter occurs error!", ec.value()); }
    if (ctr == 0) { ctr = 0; return true; }
    boost::asio::read(sock, boost::asio::buffer(reinterpret_cast<char*>(&con_size), sizeof(con_size)), ec);
    if (ec) { throw sec_gdb_network_exception("Receiving Constrian size occurs error!", ec.value()); }
    boost::asio::read(sock, boost::asio::buffer(reinterpret_cast<char*>(&con.depth), sizeof(con.depth)), ec);
    if (ec) { throw sec_gdb_network_exception("Receiving Constrian depth occurs error!", ec.value()); }
    try
    {
        for (int i = 0; i < con_size - 1; i ++) // The last one is special case
        {
            int key_size = net_recv_sized_data(sock, tmp->key);
            tmp->next = new Constrain({0});
            tmp = tmp->next;
        }
        int key_size = net_recv_sized_data(sock, tmp->key);
        tmp->next = nullptr;
    }
    catch(const sec_gdb_network_exception& e)
    {
        std::cerr << "Error message: " << e.get_msg() << " Error code: " << e.get_ec() << endl;
        throw sec_gdb_network_exception("Receiving Constrain keys occurs error!", e.get_ec()); 
    }
    catch(...)
    {
        throw sec_gdb_network_exception("Unknown error occurs during receiving Constrain!", -1);
    }
    return true;
}

bool net_send_constrain(tcp::socket& sock, GGM& ggm, Constrain& con, int ctr)
{
    boost::system::error_code ec;
    boost::asio::write(sock, boost::asio::buffer(reinterpret_cast<char*>(&ctr), sizeof(ctr)), ec);
    if (ec) { throw sec_gdb_network_exception("Sending counter occurs error!", ec.value()); }
    if (ctr == 0) { return true; }
    int con_size = 0;
    Constrain* tmp = &con;
    while (tmp)
    {
        con_size ++;
        tmp = tmp->next;
    }
    boost::asio::write(sock, boost::asio::buffer(reinterpret_cast<char*>(&con_size), sizeof(int)), ec);
    if (ec) { throw sec_gdb_network_exception("Sending Constrian size occurs error!", ec.value()); }
    boost::asio::write(sock, boost::asio::buffer(reinterpret_cast<char*>(&con.depth), sizeof(con.depth)), ec);
    if (ec) { throw sec_gdb_network_exception("Sending Constrian depth occurs error!", ec.value()); }
    try
    {
        tmp = &con;
        while(tmp)
        {
            net_send_sized_data(sock, ggm.key_size, tmp->key);
            tmp = tmp->next;
        }
    }
    catch(const sec_gdb_network_exception& e)
    {
        std::cerr << "Error message: " << e.get_msg() << " Error code: " << e.get_ec() << endl;
        throw sec_gdb_network_exception("Sending Constrain keys occurs error!", e.get_ec()); 
    }
    catch(...)
    {
        throw sec_gdb_network_exception("Unknown error occurs during sending Constrain keys!", -1);
    }
    return true;
}

void net_send_protocol_head(tcp::socket& sock, PROTOCOL_HEAD_TYPE protocol)
{
    g_protocol_ctr ++;
    usleep(500); // Ugly hack, slow down for preventing erro occuring during cleaning obliv-c protocol.
    boost::system::error_code ec;
    boost::asio::write(sock, boost::asio::buffer(&protocol, sizeof(PROTOCOL_HEAD_TYPE)), ec);
    if (ec) { throw sec_gdb_network_exception("Sending protocol head occurs error!", ec.value()); }
}

char net_recv_protocol_head(tcp::socket& sock)
{
    PROTOCOL_HEAD_TYPE protocol;
    boost::system::error_code ec;
    boost::asio::read(sock, boost::asio::buffer(&protocol, sizeof(PROTOCOL_HEAD_TYPE)), ec);
    if (ec) { throw sec_gdb_network_exception("Receiving protocol head occurs error!", ec.value()); }
    return protocol;
}