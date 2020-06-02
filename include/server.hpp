#ifndef SEC_GDB_H_SERVER
#define SEC_GDB_H_SERVER

#include <iostream>
#include <gmpxx.h>

#include <tuple>
#include <unordered_map>
#include <list>
#include <boost/heap/fibonacci_heap.hpp>
#include <boost/asio.hpp>

extern "C"
{
#include "obliv.h"
}

#include "global.h"
#include "ggm.h"
#include "crypto_stuff.hpp"
#include "graph.hpp"
#include "mpc.hpp"

/* =========================================  */
extern size_t g_fh_compare_time;
extern size_t g_s_use_cache;
extern size_t g_s_cache_size;

/* =========================================  */
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
    std::string vertex;
    mpz_class distance;
} HEAP_ITEM;

typedef struct _CACHE_ITEM
{
    std::string src;
    std::string dest;
} CACHE_ITEM;

namespace std
{
    template<>
    struct equal_to<CACHE_ITEM>
    {
        bool operator()(const CACHE_ITEM &x, const CACHE_ITEM &y) const
        {
            std::string tmp_x(x.src); tmp_x += x.dest;
            std::string tmp_y(y.src); tmp_y += y.dest;
            return tmp_x == tmp_y;
        }
    };

    template<>
    struct hash<CACHE_ITEM>
    {
        size_t operator()(const CACHE_ITEM &e) const
        {
            std::string tmp(e.src); tmp += e.dest;
            return std::hash<string>()(tmp);
        }
    };
};

class FibHeapCompare;
/* =========================================  */
class Server
{
private:
    /* friend class */
    friend FibHeapCompare;

    /* Private parameters */
    // Public keys of client
    PK pk;

    // Struct for obliv-c
    ProtocolDesc pd;

    // Boost Asio
    boost::asio::ip::tcp::socket sock;
    boost::asio::ip::tcp::endpoint proxy_info;

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
    Graph<mpz_class> sever_graph;

    // An encrypted zero.
    mpz_class zero;

    // Cache store history.
    std::unordered_map<CACHE_ITEM, mpz_class> cache;


    /* Private functions */
    // Prepare network stuff
    void network_init();

    // Prepare obliv-c stuff
    void oblivc_init();

    // Unlock an edge
    void recover_masked_edge_info(u_char* F_1_u, u_char* sub_key, std::string& P_v, std::string& F_1_v, mpz_class& ei);

    // Recover adjacency vertces of the chosen vertex
    std::vector<std::tuple<std::string, std::string, mpz_class>> unlock_adjacency_vertexes(std::string& F_1_u, Subkeys& sub_keys, int ctr);

    // Contact with proxy for getting sub keys of GGM
    int contact_and_get_ggm_sub_key(GGM& ggm, Subkeys& sub_key, std::string& P_t);

    // Contact with proxy for comparing two encryption value
    bool compare(const mpz_class& left, const mpz_class& right, int mode) const;

    // Contact with proxy for multiplying two encryption value
    mpz_class multiply (mpz_class& left, mpz_class& right);

    // Contact with proxy for calc inverse
    mpz_class inverse(mpz_class& input);

public:
    Server(boost::asio::ip::tcp::socket& sock, boost::asio::ip::tcp::endpoint& proxy_info);
    Server(const std::unordered_map<std::string, std::string> &de, const PK &pk, boost::asio::ip::tcp::socket& sock, boost::asio::ip::tcp::endpoint& proxy_info);
    ~Server();

    inline const PK &get_pk() const { return pk; }
    inline void set_params(const std::unordered_map<std::string, std::string> &de, const PK &pk)
    {
        this->D_e = de;
        this->pk = pk;
    }

    void build_server_graph(std::string &F_1_s, std::string &P_s, std::string &P_t, Constrain &constrained_key, size_t ctr);
    bool set_level(std::string &F_1_s, std::string &P_s, std::string &P_t, Constrain &constrained_key, size_t ctr);
    mpz_class augment_path(std::string &F_1_u, std::string &P_u, std::string &P_t, Constrain &constrain, size_t ctr, mpz_class gamma);
    mpz_class query_flow(std::string &F_1_s, std::string &P_s, std::string &P_t, Constrain &constrained_key, size_t ctr);
    mpz_class query_dist(std::string &F_1_s, std::string &P_s, std::string &P_t, Constrain &constrained_key, size_t ctr);
    void page_rank(std::string &F_1_s, std::string &P_s, Constrain &constrained_key, size_t ctr , int epochs);
    void unlock_graph(std::tuple<Graph<mpz_class>, Graph<mpz_class>>& double_graph, std::string& F_1_s, std::string& P_s, Constrain& constrained_key, size_t ctr);
};

/* =========================================  */
class FibHeapCompare
{
private:
    Server& server;
public:
    FibHeapCompare(Server& s): server(s) {}

    bool operator()(const HEAP_ITEM& n1, const HEAP_ITEM& n2) const
    {
        g_fh_compare_time++;
        return server.compare(n1.distance, n2.distance, COMPARE_HIGHER);
    }
};

typedef boost::heap::fibonacci_heap<HEAP_ITEM, boost::heap::compare<FibHeapCompare>> FIBO_HEAP;

#endif