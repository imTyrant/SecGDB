#ifndef SEC_GDB_H_PROXY
#define SEC_GDB_H_PROXY

#include <iostream>

#include <string>
#include <unordered_map>
#include <boost/asio.hpp>
#include <tuple>

extern "C"
{
#include "obliv.h"
}

#include "data_structures.hpp"
#include "crypto_stuff.hpp"
#include "ggm.h"

class Proxy
{
private:
    /* Private parameters */
    // Key pair
    PK pk;
    JL_SK jl_sk;

    // Boost Asio
    boost::asio::io_service& service;
    boost::asio::ip::tcp::acceptor acceptor;

    // D_pv
    std::unordered_map<std::string, V_ITEM> D_pv;

    // Private functions
    // Functions for secure multiplication
    void multiply(boost::asio::ip::tcp::socket& sock);
    
    // Function for secure comparsion
    void compare(boost::asio::ip::tcp::socket& sock, ProtocolDesc& pd);

    // Function for lookup
    std::tuple<Constrain, size_t> lookup(std::string& P_u) const;
    void lookup_remote(boost::asio::ip::tcp::socket& sock);

    // Function for parser_request
    void parse_request(boost::asio::ip::tcp::socket sock);

public:
    Proxy(boost::asio::ip::tcp::acceptor& acc, boost::asio::io_service& service);
    Proxy(const std::unordered_map<std::string, V_ITEM>& D_pv, const PK& pk, const JL_SK& jl_sk, boost::asio::ip::tcp::acceptor& acc, boost::asio::io_service& service);
    ~Proxy();

    inline JL_SK& get_jlsk() { return this->jl_sk; }
    inline JL_PK& get_jlpk() { return this->pk.jl_pk; }
    inline PK& get_pk() { return this->pk; }
    inline void set_params(const std::unordered_map<std::string, V_ITEM>& D_pv, const PK& pk, const JL_SK& jl_sk)
    {
        this->D_pv = D_pv;
        this->pk = pk;
        this->jl_sk = jl_sk;
    }

    void accept();

#ifdef SEC_GDB_SIMPLE_MODE
    friend std::tuple<Constrain, size_t> look_up(const Proxy& proxy, std::string& P_u);
#endif //SEC_GDB_SIMPLE_MODE
};

#ifdef SEC_GDB_SIMPLE_MODE
extern Proxy g_proxy;
#endif

#endif