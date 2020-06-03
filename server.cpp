#include <iostream>
#include <gmpxx.h>

#include <unordered_map>
#include <string>
#include <vector>
#include <queue>
#include <tuple>
#include <boost/heap/fibonacci_heap.hpp>
#include <boost/asio.hpp>
#include <cassert>

#include "server.hpp"

#include "ggm.h"
#include "crypto_stuff.hpp"
#include "data_structures.hpp"
#include "network.hpp"
#include "exceptions.hpp"
#include "mpc.hpp"

#ifdef SEC_GDB_SIMPLE_MODE
#include "proxy.hpp"
#endif

using namespace std;

bool Server::compare(const mpz_class& left, const mpz_class& right, int mode) const
{
    bool rtn;
    try
    {
#ifndef SEC_GDB_WITHOUT_ENCRYPTION
        net_send_protocol_head(const_cast<boost::asio::ip::tcp::socket&>(this->sock), MPC_SECURE_COMPARSION);
#endif
        rtn = (mode == secure_compare(const_cast<ProtocolDesc&>(this->pd), const_cast<JL_PK&>(this->pk.jl_pk), 
                        const_cast<mpz_class&>(left), const_cast<mpz_class&>(right), const_cast<boost::asio::ip::tcp::socket&>(this->sock)));
    }
    catch (const sec_gdb_network_exception& e)
    {
        std::cerr << "Secure compare local communication failed!\n"
                <<  "Error: " << e.get_msg() << " Error code: " << e.get_ec() << endl;
        throw sec_gdb_global_exception("Server fails to execute secure comparsion!");
    }
    
    return rtn;
}

mpz_class Server::multiply(mpz_class& left, mpz_class& right)
{
    mpz_class result;
    try
    {
#ifndef SEC_GDB_WITHOUT_ENCRYPTION
        net_send_protocol_head(sock, MPC_SECURE_MULTIPLICATION);
#endif
        result = secure_multiply(this->pk.jl_pk, left, right, sock);
    }
    catch(const sec_gdb_network_exception& e)
    {
        std::cerr << "Secure multiply local communication failed!\n"
                <<  "Error: " << e.get_msg() << " Error code: " << e.get_ec() << endl;
        throw sec_gdb_global_exception("Server fails to execute secure multiplication!");
    }
    return result;
}

mpz_class Server::inverse(mpz_class& input)
{
    mpz_class result;
    try
    {
#ifndef SEC_GDB_WITHOUT_ENCRYPTION
        net_send_protocol_head(sock, MPC_SECURE_INVERSE);
#endif
        result = secure_inverse(this->pk.jl_pk, input, sock, SCALE_SHIFT_P);
    }
    catch(const sec_gdb_network_exception& e)
    {
        std::cerr << "Secure inverse local communication failed!\n"
                <<  "Error: " << e.get_msg() << " Error code: " << e.get_ec() << endl;
        throw sec_gdb_global_exception("Server fails to calculate inverse of input!");
    }
    return result;
}

int Server::contact_and_get_ggm_sub_key(GGM& ggm, Subkeys& sub_key, string& P_t)
{
    int ctr = 0;

#ifdef SEC_GDB_SIMPLE_MODE
    auto result = look_up(g_proxy, P_t);
    Constrain& con = std::get<0>(result);
    ctr = std::get<1>(result);
    if (ctr != 0)
    {
        ggm_derive(&ggm, &con, &sub_key);
    }
    ggm_free_constrain(&con);
#else
    try
    {
        Constrain con = {0};
        net_send_protocol_head(sock, MPC_LOOK_UP);
        net_send_sized_data(sock, P_t.size(), const_cast<char*>(P_t.c_str()));
        net_recv_constrain(this->sock, ggm, con, ctr);
        print_constrain(&con, &ggm);
        if (ctr != 0)
        {
            ggm_derive(&ggm, &con, &sub_key);
        }
        ggm_free_constrain(&con);
    }
    catch(const sec_gdb_network_exception& e)
    {
        std::cerr << "Receiving Constrain occurs error!\n"
            << "Error: " << e.get_msg() << " Error code: " << e.get_ec() << endl;
        throw sec_gdb_global_exception("Server fails to derive sub key!");
    }
#endif
    return ctr;
}

void Server::recover_masked_edge_info(u_char* F_1_u, u_char* sub_key, string& P_v, string& F_1_v, mpz_class& ei)
{
    u_char UT_i[KEY_SIZE];
    u_char mask[KEY_SIZE];

    H_1(F_1_u, KEY_SIZE, sub_key, KEY_SIZE, UT_i);
    H_2(F_1_u, KEY_SIZE, sub_key, KEY_SIZE, mask);

    string UT_i_str((char*)UT_i, KEY_SIZE);
    assert(this->D_e.find(UT_i_str) != this->D_e.end());
    
    string& masked_ciph = this->D_e[UT_i_str];
    u_char ciph_i[masked_ciph.size()];
    masking(masked_ciph.c_str(), masked_ciph.length(), mask, sizeof(mask), ciph_i);

    P_v = string((char*)ciph_i, KEY_SIZE);
    F_1_v = string((char*)(ciph_i + KEY_SIZE), KEY_SIZE);
    set_mpz_raw(ei.get_mpz_t(), sizeof(ciph_i) - 2 * KEY_SIZE, ciph_i + 2 * KEY_SIZE);
}

vector<tuple<string, string, mpz_class>> Server::unlock_adjacency_vertexes(string& F_1_u, Subkeys& sub_keys, int ctr)
{
    vector<tuple<string, string, mpz_class>> rtn;
    u_char* F_1_u_char = (u_char*)F_1_u.c_str();
    for (int i = 0; i < ctr; i ++)
    {
        string P_vi, F_1_vi;
        mpz_class ei;
        recover_masked_edge_info(F_1_u_char, (u_char*)sub_keys.keys[i], P_vi, F_1_vi, ei);
        rtn.push_back(std::make_tuple(P_vi, F_1_vi, ei));
    }
    return rtn;
}

void Server::build_server_graph(string &F_1_s, string &P_s, string &P_t, Constrain &constrained_key, size_t ctr)
{   
    // vertces
    unordered_set<string> accessed_vertces;
    queue<string> q;

    accessed_vertces.emplace(P_s);

    GGM ggm = {KEY_SIZE, MAX_GGM_DEPTH};
    Subkeys sub_key;

    ggm_derive(&ggm, &constrained_key, &sub_key);

    auto neighbors = unlock_adjacency_vertexes (F_1_s, sub_key, ctr);

    for (auto each : neighbors)
    {
        string& P_v_i = std::get<0>(each);
        string& F_1_vi = std::get<1>(each);
        mpz_class& e_i = std::get<2>(each);

        this->sever_graph.add_edge(P_s, P_v_i, e_i);

        q.push(P_v_i);
        this->D_key[P_v_i] = F_1_vi;
    }

    ggm_free_keys(&sub_key);

    while(!q.empty())
    {
        string P_u = q.front();
        q.pop();
        accessed_vertces.emplace(P_u);

        Subkeys sub_keys;
        int ctr_inwhile = contact_and_get_ggm_sub_key(ggm, sub_keys, P_u);

        if (ctr_inwhile < 1) {continue;}

        auto neighbors = unlock_adjacency_vertexes(this->D_key[P_u], sub_keys, ctr_inwhile);

        for (auto each : neighbors)
        {
            string& P_v_i = std::get<0>(each);
            string& F_1_vi = std::get<1>(each);
            mpz_class& e_i = std::get<2>(each);

            this->sever_graph.add_edge(P_u, P_v_i, e_i);
            if (accessed_vertces.find(P_v_i) == accessed_vertces.end())
            {
                q.push(P_v_i);
                this->D_key[P_v_i] = F_1_vi;
            }
        }
        ggm_free_keys(&sub_keys);
    }
}

bool Server::set_level(string &F_1_s, string &P_s, string &P_t, Constrain &constrained_key, size_t ctr)
{
    queue<string> q;

    this->level.clear();
    this->level[P_s] = 0;

    q.push(P_s);

    while(!q.empty())
    {
        string P_u = q.front();
        q.pop();

        if (P_u == P_t)
        {
            return true;
        }
        
        size_t current_level = this->level[P_u];
        for (Edge<mpz_class> &e : this->sever_graph.adjacency_list[this->sever_graph.vertices[P_u]])
        {
            if (this->level.find(e.dest.name) == this->level.end() 
                    && compare(e.weight, this->zero, COMPARE_HIGHER))
            {
                q.push(e.dest.name);
                this->level.emplace(e.dest.name, current_level + 1);
            }
        }
    }

    return (this->level.find(P_t) == this->level.end()) ? false : true;
}

mpz_class Server::augment_path(string &F_1_u, string &P_u, string &P_t, Constrain &constrain, size_t ctr, mpz_class gamma)
{
    mpz_class all_cap(this->zero);
    if (P_u == P_t)
    {
        return gamma;
    }

    size_t cur_level = this->level[P_u];

    for (Edge<mpz_class> &e : this->sever_graph.adjacency_list[this->sever_graph.vertices[P_u]])
    {
        mpz_class local_cap;
        local_cap = JL_homo_sub(this->pk, gamma, all_cap);
        if (this->level.find(e.dest.name) != this->level.end() 
            && this->level[e.dest.name] == cur_level + 1)
        {
            mpz_class tmp = this->augment_path(this->D_key[e.dest.name], e.dest.name, P_t, constrain, e.dest.out_degree,
                                               compare(local_cap, e.weight, COMPARE_LOWER) ? local_cap : e.weight);

            auto rev_edge = this->sever_graph.find_edge(e.dest, e.src);
            if (rev_edge == this->sever_graph.adjacency_list[e.dest].end()) // Cannot find the edge.
            {
                this->sever_graph.add_edge(e.dest.name, e.src.name, tmp);
            }
            else
            {
                rev_edge->weight = JL_homo_add(this->pk, rev_edge->weight, tmp);
            }

            all_cap = JL_homo_add(this->pk, all_cap, tmp);
            e.weight = JL_homo_sub(this->pk, e.weight, tmp);
        }
    }

    return all_cap;
}

mpz_class Server::query_flow(string &F_1_s, string &P_s, string &P_t, Constrain &constrained_key, size_t ctr)
{
    this->sever_graph.clear();
    this->D_key.clear();

    this->build_server_graph(F_1_s, P_s, P_t, constrained_key, ctr);

    mpz_class c_qf;
    JL_encryption(this->pk, 0, c_qf);

    mpz_class inf;
    JL_encryption(this->pk, SEC_GDB_INF, inf);

    while(set_level(F_1_s, P_s, P_t, constrained_key, ctr))
    {
        mpz_class tmp = augment_path(F_1_s, P_s, P_t, constrained_key, ctr, inf);
        c_qf = JL_homo_add(this->pk, c_qf, tmp);
    }

    return c_qf;
}

mpz_class Server::query_dist(std::string &F_1_s, std::string &P_s, std::string &P_t, Constrain &constrained_key, size_t ctr)
{
    CACHE_ITEM cache_tmp = {P_s, P_t};
    if (this->cache.find(cache_tmp) != this->cache.end())
    {
        g_s_use_cache++;
        return this->cache[cache_tmp];
    }

    mpz_class c_qd;
    JL_encryption(this->pk, 0, c_qd);

    FibHeapCompare cmp(*this); // Initializing custom compare function.
    FIBO_HEAP fh(cmp); // Initializing a fibonacci heap.

    unordered_map<string, FIBO_HEAP::handle_type> heap_handlers; // Use a hash table to access the vertex added into heap.
    unordered_set<string> chosen_vertices;

    this->xi.clear();
    this->D_key.clear();
    this->path.clear();

    // The reason of these steppes is for preventing source vertex from being chosen again.
    xi[P_s] = this->zero;
    path[P_s] = PATH_ITEM{P_s, this->zero};
    heap_handlers[P_s] = fh.push(HEAP_ITEM{P_s, this->zero});
    fh.pop();
    chosen_vertices.emplace(P_s); //Important!

    GGM ggm = {KEY_SIZE, MAX_GGM_DEPTH};
    Subkeys sub_keys;
    ggm_derive(&ggm, &constrained_key, &sub_keys);
    auto neighbors = unlock_adjacency_vertexes(F_1_s, sub_keys, ctr);

    for (auto each : neighbors)
    {
        string& P_v_i = std::get<0>(each);
        string& F_1_vi = std::get<1>(each);
        mpz_class& e_i = std::get<2>(each);

        this->path[P_v_i] = PATH_ITEM{P_s, e_i};
        this->xi[P_v_i] = e_i;
        FIBO_HEAP::handle_type handler =  fh.push(HEAP_ITEM{P_v_i, xi[P_v_i]});
        heap_handlers[P_v_i] = handler;
        this->D_key[P_v_i] = F_1_vi;
    }

    ggm_free_keys(&sub_keys);

    while(!fh.empty())
    {
        HEAP_ITEM hi = fh.top();
        fh.pop();
        chosen_vertices.emplace(hi.vertex);

        string &P_u = hi.vertex;
        if (P_u == P_t)
        {
            this->cache.emplace(cache_tmp, xi[P_u]);
            string tmp = let_mpz_raw_to_str(xi[P_u].get_mpz_t());
            g_s_cache_size += 2 * KEY_SIZE + tmp.size();
            return xi[P_u];
        }

        Subkeys sub_keys;
        int ctr_inwhile = contact_and_get_ggm_sub_key(ggm, sub_keys, P_u);

        if (ctr_inwhile < 1) {continue;}

        auto neighbors = unlock_adjacency_vertexes(this->D_key[P_u], sub_keys, ctr_inwhile);

        for (auto each : neighbors)
        {
            string& P_v_i = std::get<0>(each);
            string& F_1_vi = std::get<1>(each);
            mpz_class& e_i = std::get<2>(each);

            // If cannot find P_v_i in xi, the latter condition may cause error.
            // Also the first condition checks whether P_v_i is accessed.
            // if (xi.find(P_v_i) == xi.end() || xi[P_u] + e_i < xi[P_v_i]) 
            mpz_class tmp(JL_homo_add(this->pk, xi[P_u], e_i));
            if (xi.find(P_v_i) == xi.end() || compare(tmp, xi[P_v_i], COMPARE_LOWER)) 
            {
                xi[P_v_i] = tmp;
                path[P_v_i] = PATH_ITEM{P_u, e_i};
            }

            if (heap_handlers.find(P_v_i) == heap_handlers.end())
            {
                FIBO_HEAP::handle_type handler = fh.push(HEAP_ITEM{P_v_i, xi[P_v_i]});
                heap_handlers[P_v_i] = handler;
            }
            else
            {
                // Check if the P_v_i has been chosen, namely the distance of 
                // P_v_i is shortest.
                if (chosen_vertices.find(P_v_i) == chosen_vertices.end()) 
                {
                    fh.update(heap_handlers[P_v_i], HEAP_ITEM{P_v_i, xi[P_v_i]});
                }
            }

            D_key[P_v_i] = F_1_vi;
        }

        ggm_free_keys(&sub_keys);
    }
    this->cache.emplace(cache_tmp, c_qd);
    string tmp = let_mpz_raw_to_str(c_qd.get_mpz_t());
    g_s_cache_size += 2 * KEY_SIZE + tmp.size();
    return c_qd;
}


void Server::normalize_graph_outedge_weight(tuple<Graph<mpz_class>, Graph<mpz_class>>& double_graph)
{
    auto& graph = std::get<0>(double_graph);
    auto& reverse_graph = std::get<1>(double_graph);
    for (auto vit = graph.vertices.begin(); vit != graph.vertices.end(); vit ++)
    {
        auto& vertex_name = vit->first;
        auto& vertex_info = vit->second;
        mpz_class weight_sum;
        JL_encryption(pk, 0, weight_sum);

        for (auto eit = graph.adjacency_list[vertex_info].begin(); eit != graph.adjacency_list[vertex_info].end(); eit ++)
        {
            weight_sum = JL_homo_add(pk, weight_sum, eit->weight);
        }

        for (auto eit = graph.adjacency_list[vertex_info].begin(); eit != graph.adjacency_list[vertex_info].end(); eit ++)
        {
            // Divide edge weight by weight sum
            mpz_class sum_ivs = inverse(weight_sum);
            mpz_class new_weight = multiply(eit->weight, sum_ivs);
            // Update each edge
            graph.modify_edge(eit->src.name, eit->dest.name, new_weight);
            reverse_graph.modify_edge(eit->dest.name, eit->src.name, new_weight);
        }
    }
}

void Server::unlock_graph(tuple<Graph<mpz_class>, Graph<mpz_class>>& double_graph, string& F_1_s, string& P_s, Constrain& constrained_key, size_t ctr)
{
    queue<string> q;
    Graph<mpz_class>& graph = std::get<0>(double_graph); // graph for out edges
    Graph<mpz_class>& reverse_graph = std::get<1>(double_graph); // graph for in edges
    GGM ggm = {KEY_SIZE, MAX_GGM_DEPTH};

    Subkeys sub_keys;
    ggm_derive(&ggm, &constrained_key, &sub_keys);
    auto neighbors = unlock_adjacency_vertexes(F_1_s, sub_keys, ctr);
    ggm_free_keys(&sub_keys);

    for (auto each : neighbors)
    {
        string& P_v = std::get<0>(each);
        string& F_1_v = std::get<1>(each);
        mpz_class& ei = std::get<2>(each);

        if (graph.vertices.find(P_v) == graph.vertices.end())
        {
            q.push(P_v);
            this->D_key[P_v] = F_1_v;
        }
        graph.add_edge(P_s, P_v, ei);
        reverse_graph.add_edge(P_v, P_s, ei);
    }

    while (!q.empty())
    {
        string P_u = q.front();
        q.pop();
        
        Subkeys sub_keys;
        int ctr = contact_and_get_ggm_sub_key(ggm, sub_keys, P_u);
        if (ctr < 1) {continue;}
        auto neighbors = unlock_adjacency_vertexes(this->D_key[P_u], sub_keys, ctr);
        for (auto each : neighbors)
        {
            string& P_v = std::get<0>(each);
            string& F_1_v = std::get<1>(each);
            mpz_class& ei = std::get<2>(each);

            if (graph.vertices.find(P_v) == graph.vertices.end())
            {
                q.push(P_v);
                this->D_key[P_v] = F_1_v;
            }
            graph.add_edge(P_u, P_v, ei);
            reverse_graph.add_edge(P_v, P_u, ei);
        }
        ggm_free_keys(&sub_keys);
    }
}

void Server::page_rank(std::string &F_1_s, std::string &P_s, Constrain &constrained_key, size_t ctr, int epochs)
{
    size_t base = (1 << SCALE_SHIFT_P);
    size_t long_d = (size_t)(float(base) * SEC_GDB_PAGE_RANK_D);
    mpz_class raw_d(long_d), one_sub_d(base - long_d);
    mpz_class enc_d, enc_1sd;
    JL_encryption(this->pk.jl_pk, raw_d, enc_d);
    JL_encryption(this->pk.jl_pk, one_sub_d, enc_1sd);

    auto double_graph = std::make_tuple(Graph<mpz_class>(), Graph<mpz_class>());
    unlock_graph(double_graph, F_1_s, P_s, constrained_key, ctr);
    normalize_graph_outedge_weight(double_graph);
    Graph<mpz_class>& graph = std::get<0>(double_graph); // graph for out edges
    Graph<mpz_class>& reverse_graph = std::get<1>(double_graph); // graph for in edges

    unordered_map<Vertex, mpz_class> PR_list;
    for (auto it = graph.vertices.begin(); it != graph.vertices.end(); it ++)
    {
        mpz_class one;
        JL_encryption(this->pk, 1, one);
        PR_list[it->second] = one;
    }

    for (int e = 0; e < epochs; e ++)
    {
        for (auto it = PR_list.begin(); it != PR_list.end(); it ++)
        {
            auto& pr_value = it->second;
            auto& vertex = it->first;
            for (auto adj_it = reverse_graph.adjacency_list[vertex].begin(); adj_it != reverse_graph.adjacency_list[vertex].end(); adj_it ++)
            {
                mpz_class mul = multiply(PR_list[adj_it->dest], adj_it->weight);
                pr_value = JL_homo_add(this->pk, pr_value, mul);
            }
            pr_value = JL_homo_mul(this->pk, pr_value, raw_d);
            pr_value = JL_homo_add(this->pk, pr_value, enc_1sd);
        }
    }
}

void Server::network_init()
{
    this->sock.connect(proxy_info);
    this->sock.set_option(boost::asio::ip::tcp::no_delay(true));
}

void Server::oblivc_init()
{
    /* Init new pd in each round of secure comparsion */

    // int skn = sock.native_handle();
    // protocolUseTcp2PKeepAlive(&pd, skn, true);
}

Server::Server(boost::asio::ip::tcp::socket& sock, boost::asio::ip::tcp::endpoint& proxy_info)
    : D_e(), pk(), level(), D_key(), xi(), path(), sever_graph(),
        zero(), cache(), pd({0}), sock(std::move(sock)), proxy_info(proxy_info)
{
    JL_encryption(this->pk, 0, this->zero);
    network_init();
    oblivc_init();
}
Server::Server(const unordered_map<string, string> &de, const PK &pk, boost::asio::ip::tcp::socket& sock, boost::asio::ip::tcp::endpoint& proxy_info)
    : D_e(de), pk(pk), level(), D_key(), xi(), path(), sever_graph(),
        zero(), cache(), pd({0}), sock(std::move(sock)), proxy_info(proxy_info)
{
    JL_encryption(this->pk, 0, this->zero);
    network_init();
    oblivc_init();
}

Server::~Server()
{
    // cleanupProtocol(&pd);
    sock.close();
}