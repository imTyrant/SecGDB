#ifndef SEC_GDB_H_SERVER
#define SEC_GDB_H_SERVER

#include <iostream>
#include <gmpxx.h>

#include <unordered_map>
#include <list>
#include <boost/heap/fibonacci_heap.hpp>

#include "global.h"
#include "ggm.h"
#include "crypto_stuff.hpp"
#include "graph.hpp"

#include "client.hpp"
#include "sec_compare.hpp"

typedef struct _ENC_E_ITEM
{
    std::string s;
    std::string d;
}ENC_E_ITEM;

namespace std
{
    template<>
    struct equal_to<ENC_E_ITEM>
    {
        bool operator()(const ENC_E_ITEM &x, const ENC_E_ITEM &y) const
        {
            std::string tmp_x(x.s); tmp_x += x.d;
            std::string tmp_y(y.s); tmp_y += y.d;
            return tmp_x == tmp_y;
        }
    };

    template<>
    struct hash<ENC_E_ITEM>
    {
        size_t operator()(const ENC_E_ITEM &e) const
        {
            std::string tmp(e.s); tmp += e.d;
            return std::hash<string>()(tmp);
        }
    };
};

typedef struct _PATH_ITEM
{
    std::string prev;
    mpz_class weight;
} PATH_ITEM;

typedef struct _HEAP_ITEM
{
    std::string vetex;
    mpz_class distance;
} HEAP_ITEM;

struct heap_item_compare
{
    bool operator()(const HEAP_ITEM& n1, const HEAP_ITEM& n2) const
    {
        return secure_compare_greater(g_client.get_pk(), const_cast<mpz_class&>(n1.distance),  const_cast<mpz_class&>(n2.distance));
        // return n1.distance > n2.distance;
    }
};

typedef boost::heap::fibonacci_heap<HEAP_ITEM, boost::heap::compare<heap_item_compare>> FIBO_HEAP;

class Server
{
  private:
    PK pk;
    
    // The D_e as same as the one in client.
    std::unordered_map<std::string, std::string> D_e;
    // Stroe F_1_X keys for each P_X
    std::unordered_map<std::string, std::string> D_key;

    // Parameters used during find max flow.
    std::unordered_map<ENC_E_ITEM, mpz_class> cap_r;

    std::unordered_map<std::string, size_t> level;

    // Parameters used during find shortest distance.
    std::unordered_map<std::string, PATH_ITEM> path;

    std::unordered_map<std::string, mpz_class> xi;

    // Store an temporary graph in server with blinded vertex and encrypted weight.
    std::unordered_map<std::string, std::list<Edge>> verteices;


  public:
    Server();
    Server(const std::unordered_map<std::string, std::string> &de, const PK &pk);
    ~Server();

    bool set_level(std::string &F_1_s, std::string &P_s, std::string &P_t, Constrain &constrained_key, size_t ctr);
    mpz_class augment_path(std::string &F_1_u, std::string &P_u, std::string &P_t, Constrain &constrain, size_t ctr, mpz_class gamma);
    mpz_class query_flow(std::string &F_1_s, std::string &P_s, std::string &P_t, Constrain &constrained_key, size_t ctr);
    mpz_class query_dist(std::string &F_1_s, std::string &P_s, std::string &P_t, Constrain &constrained_key, size_t ctr);
};

#endif