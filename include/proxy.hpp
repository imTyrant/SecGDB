#ifndef SEC_GDB_H_PROXY
#define SEC_GDB_H_PROXY

#include <iostream>

#include <string>
#include <unordered_map>
#include <tuple>

#include "data_structures.hpp"
#include "crypto_stuff.hpp"
#include "ggm.h"


class Proxy
{
private:
    std::unordered_map<std::string, V_ITEM> D_pv;
    PK pk;
    JL_SK jl_sk;

public:
    Proxy();
    Proxy(const std::unordered_map<std::string, V_ITEM>& D_pv, const PK& pk, const JL_SK& jl_sk);
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
    std::tuple<Constrain, size_t> look_up(std::string& P_u);
};

#ifdef SEC_GDB_SIMPLE_MODE
extern Proxy g_proxy;
#endif

#endif