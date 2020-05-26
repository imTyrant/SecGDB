#ifndef SEC_GDB_H_PROXY
#define SEC_GDB_H_PROXY

#include <iostream>

#include <string>
#include <unordered_map>

#include "data_structures.hpp"
#include "crypto_stuff.hpp"
#include "ggm.h"

class Proxy
{
private:
    std::unordered_map<std::string, V_ITEM> D_e;
    PK pk;

public:
    Proxy(std::unordered_map<std::string, V_ITEM> D_e, PK pk);
    ~Proxy();

    Constrain look_up(std::string P_u);
};


#endif