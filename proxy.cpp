#include <iostream>

#include <unordered_map>

#include <gmpxx.h>

#include "proxy.hpp"

#include "global.h"
#include "crypto_stuff.hpp"
#include "data_structures.hpp"
#include "ggm.h"

using namespace std;

Constrain Proxy::look_up(string P_u)
{
    GGM ggm;
    ggm.key_size = KEY_SIZE;
    ggm.n = MAX_GGM_DEPTH;

    Constrain rtn;

    V_ITEM v_itme = this->D_e[P_u];

    if (v_itme.ctr != 0)
    {
        ggm_find_best_range_cover(&ggm, const_cast<char*>(v_itme.master_key.c_str()), 0, v_itme.ctr - 1, &rtn);
    }

    return rtn;
}

Proxy::Proxy(unordered_map<string, V_ITEM> D_e, PK pk) : D_e(D_e), pk(pk)
{

}

Proxy::~Proxy()
{
}
