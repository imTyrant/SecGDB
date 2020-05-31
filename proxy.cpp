#include <iostream>
#include <tuple>
#include <unordered_map>

#include <gmpxx.h>

#include "proxy.hpp"

#include "global.h"
#include "crypto_stuff.hpp"
#include "data_structures.hpp"
#include "ggm.h"

using namespace std;

tuple<Constrain, size_t> Proxy::look_up(string& P_u)
{
    GGM ggm;
    ggm.key_size = KEY_SIZE;
    ggm.n = MAX_GGM_DEPTH;

    Constrain rtn;

    V_ITEM v_item = this->D_pv[P_u];

    if (v_item.ctr != 0)
    {
        ggm_find_best_range_cover(&ggm, const_cast<char*>(v_item.master_key.c_str()), 0, v_item.ctr - 1, &rtn);
    }
    
    return make_tuple(rtn, v_item.ctr);
}

Proxy::Proxy()
    : D_pv(), pk(), jl_sk()
{
    
}

Proxy::Proxy(const unordered_map<string, V_ITEM>& D_pv, const PK& pk, const JL_SK& jl_sk)
    : D_pv(D_pv), pk(pk), jl_sk(jl_sk)
{
}

Proxy::~Proxy()
{
}
