#include <iostream>
#include <tuple>
#include <unordered_map>
#include <thread>
#include <utility>

#include <gmpxx.h>

#include "proxy.hpp"

#include "global.h"
#include "exceptions.hpp"
#include "network.hpp"
#include "crypto_stuff.hpp"
#include "mpc.hpp"
#include "data_structures.hpp"
#include "ggm.h"

using namespace std;
using namespace boost::asio;

void Proxy::compare(ip::tcp::socket& sock, ProtocolDesc& pd)
{
    try
    {
        secure_compare_remote(pd, this->pk.jl_pk, this->jl_sk, sock);
    }
    catch (const sec_gdb_network_exception& e)
    {
        std::cerr << "Secure compare remote communication failed!\n"
                <<  "Error: " << e.get_msg() << " Error code: " << e.get_ec() << endl;
        throw sec_gdb_global_exception("Proxy fails to excute secure comparsion!");
    }
}

void Proxy::multiply(ip::tcp::socket& sock)
{
    try
    {
        secure_multiply_remote(this->pk.jl_pk, this->jl_sk, sock);
    }
    catch (const sec_gdb_network_exception& e)
    {
        std::cerr << "Secure multiply remote communication failed!\n"
                <<  "Error: " << e.get_msg() << " Error code: " << e.get_ec() << endl;
        throw sec_gdb_global_exception("Proxy fails to excute secure multiplicaion");
    }
}

void Proxy::lookup_remote(ip::tcp::socket& sock)
{
    GGM ggm;
    ggm.key_size = KEY_SIZE;
    ggm.n = MAX_GGM_DEPTH;
    try
    {
        char* buff = nullptr;
        int size = net_recv_sized_data(sock, buff);
        string P_u(buff);
        auto result = lookup(P_u);
        net_send_constrain(sock, ggm, std::get<0>(result), std::get<1>(result));
        delete buff;
    }
    catch(const sec_gdb_network_exception& e)
    {
        std::cerr << "Proxy occurs error during looking up!\n"
            << "Error: " << e.get_msg() << " Error code " << e.get_ec() << endl;
        throw sec_gdb_global_exception("Proxy fails to look up!");
    }
}

#ifdef SEC_GDB_SIMPLE_MODE
tuple<Constrain, size_t> look_up(const Proxy& proxy, string& P_u)
{
    return proxy.lookup(P_u);
}
#endif // SEC_GDB_SIMPLE_MODE

tuple<Constrain, size_t> Proxy::lookup(string& P_u) const
{
    GGM ggm;
    ggm.key_size = KEY_SIZE;
    ggm.n = MAX_GGM_DEPTH;

    Constrain rtn;

    V_ITEM v_item = this->D_pv.at(P_u);;

    if (v_item.ctr != 0)
    {
        ggm_find_best_range_cover(&ggm, const_cast<char*>(v_item.master_key.c_str()), 0, v_item.ctr - 1, &rtn);
    }
    
    return make_tuple(rtn, v_item.ctr);
}


void Proxy::parse_request(ip::tcp::socket sock)
{
    ProtocolDesc pd = {0};
    protocolUseTcp2PKeepAlive(&pd, sock.native_handle(), false);
    while(true)
    {
        try
        {
            PROTOCOL_HEAD_TYPE protocol = MPC_EMPTY_PROTOCOL;
            switch (protocol)
            {
                case MPC_SECURE_COMPARSION:
                    compare(sock, pd);
                    break;
                case MPC_SECURE_MULTIPLICATION:
                    multiply(sock);
                    break;
                case MPC_LOOK_UP:
                    lookup_remote(sock);
                    break;
                default:
                    break;
            }
        }
        catch (const sec_gdb_network_exception& e)
        {
            std::cerr << "Proxy fails to get requests!\n"
                    << "Error: " << e.get_msg() << " Error code: " << e.get_ec() << endl;
            break;
        }
        catch (const sec_gdb_global_exception& e)
        {
            std::cerr << "Error: " << e.get_msg() << endl;
            break;
        }
    }
    cleanupProtocol(&pd);
    sock.close();
}

void Proxy::accept()
{
    ip::tcp::socket sock(service);
    while(true)
    {
        acceptor.accept(sock);
        parse_request(std::move(sock));
        // std::thread(parse_request, std::move(sock)).detach();
    }
}

Proxy::Proxy(ip::tcp::acceptor& acc, io_service& service)
    : D_pv(), pk(), jl_sk(), service(service), acceptor(std::move(acc))
{
}

Proxy::Proxy(const unordered_map<string, V_ITEM>& D_pv, const PK& pk, const JL_SK& jl_sk,ip::tcp::acceptor& acc, io_service& service)
    : D_pv(D_pv), pk(pk), jl_sk(jl_sk), service(service), acceptor(std::move(acc))
{
}

Proxy::~Proxy()
{
}
