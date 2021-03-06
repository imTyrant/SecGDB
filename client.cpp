#include <iostream>
#include <algorithm>
#include <iomanip>
#include <chrono>
#include <fstream>

#include <string>
#include <unordered_map>
#include <vector>

#include <gmpxx.h>

#include "client.hpp"
#include "ggm.h"
#include "graph.hpp"
#include "crypto_stuff.hpp"
#include "data_structures.hpp"

using namespace std;

void Client::load_dcv(const string &filePath)
{
    if(!load_Dv(filePath, this->D_cv)) {cerr << "Loading D_cv failed." << endl;};
}

void Client::load_dpv(const string &filePath)
{
    if(!load_Dv(filePath, this->D_pv)) {cerr << "Loading D_pv failed." << endl;};
}

void Client::load_de(const string &filePath)
{
    if(!load_De(filePath, this->D_e)) {cerr << "Loading D_e failed." << endl;};
}

void Client::save_dcv(const string &filePath)
{
    if (!save_Dv(filePath, this->D_cv)) { cerr << "Saving D_cv failed." << endl;};
}

void Client::save_dpv(const string &filePath)
{
    if (!save_Dv(filePath, this->D_pv)) { cerr << "Saving D_pv failed." << endl;};
}

void Client::save_de(const string &filePath)
{
    if (!save_De(filePath, this->D_e)) { cerr << "Saving D_e failed." << endl;};
}

void Client::update_graph(const std::string &src, const std::string &dest, const size_t weight, int op)
{
    auto timer_client_start = chrono::high_resolution_clock::now();
    unsigned char F_1_s[KEY_SIZE] = {0};
    unsigned char F_2_s[KEY_SIZE] = {0};
    unsigned char P_s[KEY_SIZE] = {0};
    unsigned char F_1_t[KEY_SIZE] = {0};
    unsigned char F_2_t[KEY_SIZE] = {0};
    unsigned char P_t[KEY_SIZE] = {0};

    F((unsigned char *)sk.k_1.c_str(), sk.k_1.size(), (unsigned char *)src.c_str(), src.size(), F_1_s);
    F((unsigned char *)sk.k_2.c_str(), sk.k_2.size(), (unsigned char *)src.c_str(), src.size(), F_2_s);
    F((unsigned char *)sk.k_3.c_str(), sk.k_3.size(), (unsigned char *)src.c_str(), src.size(), P_s);

    F((unsigned char *)sk.k_1.c_str(), sk.k_1.size(), (unsigned char *)dest.c_str(), src.size(), F_1_t);
    F((unsigned char *)sk.k_2.c_str(), sk.k_2.size(), (unsigned char *)dest.c_str(), src.size(), F_2_t);
    F((unsigned char *)sk.k_3.c_str(), sk.k_3.size(), (unsigned char *)dest.c_str(), src.size(), P_t);

    if (op == SEC_GDB_UPDATE_OP_ADD)
    {
        // Update local.
        if (this->D_cv.find(src) == this->D_cv.end())
        {
            this->D_cv[src] = V_ITEM{0, string((char*)F_2_s, KEY_SIZE)};
        }
        this->D_cv[src].ctr += 1;

        GGM ggm = {KEY_SIZE, MAX_GGM_DEPTH};
        Constrain con;
        Subkeys subk;

        ggm_find_best_range_cover(&ggm, (char*)this->D_cv[src].master_key.c_str(), this->D_cv[src].ctr - 1, this->D_cv[src].ctr - 1, &con);
        ggm_derive(&ggm, &con, &subk);

        unsigned char UT[KEY_SIZE] = {0};
        unsigned char mask[KEY_SIZE] = {0};

        H_1(F_1_s, KEY_SIZE, (unsigned char*)subk.keys[0], KEY_SIZE, UT);
        H_2(F_1_s, KEY_SIZE, (unsigned char *)subk.keys[0], KEY_SIZE, mask);

        mpz_class w(weight);
        string weight_str = let_mpz_raw_to_str(w.get_mpz_t());

        unsigned char data[KEY_SIZE * 2 + weight_str.size()] = {0};

        std::copy(P_t, P_t + KEY_SIZE, data);
        std::copy(F_1_t, F_1_t + KEY_SIZE, data + KEY_SIZE);
        std::copy(weight_str.begin(), weight_str.end(), data + 2 * KEY_SIZE);

        unsigned char data_masked[KEY_SIZE * 2 + weight_str.size()] = {0};

        masking(data, sizeof(data), mask, sizeof(mask), data_masked);

        auto timer_client_finish = chrono::high_resolution_clock::now();
        chrono::duration<double> time_client = timer_client_finish - timer_client_start;
        g_c_update_clt = time_client.count();

        // Update proxy.
        auto timer_proxy_start = chrono::high_resolution_clock::now();
        string str_P_s((char*)P_s, KEY_SIZE);

        if (this->D_pv.find(str_P_s) == this->D_pv.end())
        {
            this->D_cv[str_P_s] = V_ITEM{0, string((char*)F_2_s, KEY_SIZE)};
        }
        this->D_cv[str_P_s].ctr += 1;
        auto timer_proxy_finish = chrono::high_resolution_clock::now();
        chrono::duration<double> time_proxy = timer_proxy_finish - timer_proxy_start;
        g_c_update_prxy = time_proxy.count();

        // Update server.
        auto timer_server_start = chrono::high_resolution_clock::now();

        this->D_e[string((char *)UT, sizeof(UT))] = string((char *)data_masked, sizeof(data_masked));

        auto timer_server_finish = chrono::high_resolution_clock::now();
        chrono::duration<double> time_server = timer_server_finish - timer_server_start;
        g_c_update_srv = time_server.count();

        ggm_free_constrain(&con);
        ggm_free_keys(&subk);
        return;
    }
    if (op == SEC_GDB_UPDATE_OP_DEL)
    {
        
        return;
    }
}

Request Client::give_request(std::string src, std::string dest)
{
    Request rtn;
    GGM ggm = {KEY_SIZE, MAX_GGM_DEPTH};

    if (this->D_cv.find(src) == this->D_cv.end() ||
        this->D_cv.find(dest) == this->D_cv.end())
    {   
        rtn.validity = false;
        return rtn;
    }

    if (src == dest || this->graph.vertices[src].out_degree == 0 || this->graph.vertices[dest].in_degree == 0)
    {
        rtn.validity = false;
        return rtn;
    }

    rtn.validity = true;
    rtn.ctr = this->D_cv[src].ctr;

    ggm_find_best_range_cover(&ggm, (char*)this->D_cv[src].master_key.c_str(), 0, rtn.ctr, &rtn.constrained_key);
    
    unsigned char F_1_s[KEY_SIZE];
    unsigned char P_s[KEY_SIZE];
    unsigned char P_t[KEY_SIZE];

    F((unsigned char*)sk.k_1.c_str(), sk.k_1.length(), (unsigned char*)src.c_str(), src.length(), F_1_s);
    F((unsigned char*)sk.k_3.c_str(), sk.k_3.length(), (unsigned char*)src.c_str(), src.length(), P_s);
    F((unsigned char*)sk.k_3.c_str(), sk.k_3.length(), (unsigned char*)dest.c_str(), dest.length(), P_t);

    rtn.F_1_s = string((char*)F_1_s, KEY_SIZE);
    rtn.P_s = string((char*)P_s, KEY_SIZE);
    rtn.P_t = string((char*)P_t, KEY_SIZE);

    return rtn;
}

void Client::enc_graph(const string &file_path, int scaler)
{
    build_graph(this->graph, file_path);

    size_t base = 1 << scaler;

    for (auto v : this->graph.vertices)
    {
        size_t ctr = v.second.out_degree;

        unsigned char F_1_u[KEY_SIZE] = {0};
        unsigned char F_2_u[KEY_SIZE] = {0};
        unsigned char P_u[KEY_SIZE] = {0};

        //Get F_1(u)
        F((unsigned char*)sk.k_1.c_str(), sk.k_1.size(), (unsigned char*)v.second.name.c_str(), v.second.name.length(), F_1_u);

        //Get F_2(u)
        F((unsigned char*)sk.k_2.c_str(), sk.k_2.size(), (unsigned char*)v.second.name.c_str(), v.second.name.length(), F_2_u);

        //Get P(u)
        F((unsigned char*)sk.k_3.c_str(), sk.k_3.size(),  (unsigned char*)v.second.name.c_str(), v.second.name.length(), P_u);

        this->D_cv[v.second.name] = V_ITEM{ctr, string((char*)F_2_u, KEY_SIZE)};
        this->D_pv[string((char*)P_u, KEY_SIZE)] = V_ITEM{ctr, string((char*)F_2_u, KEY_SIZE)};
        this->D_v2p[v.second.name] = string((char*)P_u, KEY_SIZE);

        // The following operations should be done under the condition 
        // that current vertex out degree is not 0, so we have to check v's out degree.
        if (ctr == 0)
        {
            continue;
        }

        // In here all of constrained keys have been generated, a little different
        // from the design in the paper.
        // Namely for each QT_i has got and been stored in sub_keys.
        GGM ggm;
        ggm.key_size = KEY_SIZE;
        ggm.n = MAX_GGM_DEPTH;

        Constrain constrain;


        ggm_find_best_range_cover(&ggm, (char*)F_2_u, 0, ctr - 1, &constrain);

        Subkeys sub_keys;

        ggm_derive(&ggm, &constrain, &sub_keys);

        int i = 0;
        // if (v.first == "2")
        // {
        //     cout << sub_keys.num << endl;
        //     print_constrain(&constrain, &ggm);
        // }
        for (auto e : this->graph.adjacency_list[v.second])
        {
            //Firstly, encrypt the weight of the each edge of the vertex v.
            E_ITEM data_tmp;

            size_t weight_scaler = (size_t)(float(e.weight) * float(base));

            JL_encryption(this->pk, weight_scaler, data_tmp.weight);

            unsigned char F_1_v[KEY_SIZE];
            unsigned char P_v[KEY_SIZE];

            //Get F_1(v)
            F((unsigned char*)sk.k_1.data(), sk.k_1.size(), (unsigned char*)e.dest.name.c_str(), e.dest.name.length(), F_1_v);

            //Get P(v)
            F((unsigned char*)sk.k_3.data(), sk.k_1.size(), (unsigned char*)e.dest.name.c_str(), e.dest.name.length(), P_v);
            
            data_tmp.master_key = string((char*)F_1_v, KEY_SIZE);
            data_tmp.index = string((char*)P_v, KEY_SIZE);

            unsigned char UT_i[KEY_SIZE] = {0};
            unsigned char mask[KEY_SIZE] = {0};

            // if (v.first == "2")
            // {
            //     for (int idx = 0 ; idx < KEY_SIZE; idx ++)
            //         printf("%2hhx ", sub_keys.keys[i][idx]);
            //     printf("\n");
            // }

            //Get UT_i
            H_1(F_1_u, KEY_SIZE, (unsigned char*)sub_keys.keys[i], KEY_SIZE, UT_i);

            //Get the mask part to blind data.
            H_2(F_1_u, KEY_SIZE, (unsigned char *)sub_keys.keys[i], KEY_SIZE, mask);

            // Now use H_2(F_1(u), QT_i) to mask data.
            string weight_str = let_mpz_raw_to_str(data_tmp.weight.get_mpz_t());
            
            unsigned char data[KEY_SIZE * 2 + weight_str.size()] = {0};

            std::copy(P_v, P_v + KEY_SIZE, data);
            std::copy(F_1_v, F_1_v + KEY_SIZE, data + KEY_SIZE);
            std::copy(weight_str.begin(), weight_str.end(), data + 2 * KEY_SIZE);

            unsigned char data_masked[KEY_SIZE * 2 + weight_str.size()] = {0};

            masking(data, sizeof(data), mask, sizeof(mask), data_masked);

            //remember! the size is important!
            this->D_e[string((char*)UT_i, sizeof(UT_i))] = string((char*)data_masked, sizeof(data_masked));
            i++;
        }

        ggm_free_keys(&sub_keys);

        ggm_free_constrain(&constrain);
    }
}



Client::Client() : graph(), D_pv(), D_e(), D_cv(), D_v2p()
{
    sample_key(this->sk, this->pk);
}

Client::~Client()
{
    sk_clear(this->sk);
    pk_clear(this->pk);
}

#ifdef SEC_GDB_DBG_CLIENT
int main(int argc, char *argv[])
{
    Client c;
    c.enc_graph("./data/little.txt");

    char a1[] = {'1', '2', '3', 0, '4' , '5'};

}
#endif

//g++ -g client.cpp ./util/crypto_stuff.cpp ./util/graph.cpp ./util/ggm.c ./labhe/build/liblabhe.a -lgmpxx -lgmp -lcrypto -I ./include/ -I labhe/include/ -Wall