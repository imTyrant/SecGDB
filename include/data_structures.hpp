#ifndef SEC_GDB_H_DV
#define SEC_GDB_H_DV

#include <iostream>
#include <gmpxx.h>

#include "global.h"
#include "ggm.h"


typedef struct _V_ITEM
{
    size_t ctr;
    std::string master_key; //F_2(u)
} V_ITEM;

typedef struct _E_ITEM
{
    std::string index;      //P(u)
    std::string master_key; //F_1(v)
    mpz_class weight;     //e_i
} E_ITEM;

/**
 * This code is used for unordered_map.
 * Override the hash function for mpz_t.
*/
namespace std
{
template <>
struct hash<mpz_t>
{
    size_t operator()(const mpz_t &x) const
    {
        std::size_t h = 0;
        for (int i = 0; i < abs(x->_mp_size); ++i)
            h ^= std::hash<mp_limb_t>()(x->_mp_d[i]);
        return h;
    }
};
} // namespace std

typedef struct _REQUEST
{
    std::string F_1_s;
    std::string P_s;
    std::string P_t;
    Constrain constrained_key;
    size_t ctr;
    bool validity;
} Request;

#endif