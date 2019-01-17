#include <iostream>
#include <algorithm>
#include <iomanip>

#include <string>
#include <unordered_map>
#include <vector>

#include <gmpxx.h>

#include "client.hpp"
#include "ggm.h"
#include "graph.hpp"
#include "crypto_stuff.hpp"
#include "dictionary_items.hpp"

using namespace std;

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

void Client::enc_graph(const string &file_path)
{
    this->graph.build_graph(file_path);

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
        for (auto e : this->graph.adjacency_list[v.second])
        {
            //Firstly, encrypt the weight of the each edge of the vertex v.
            E_ITEM data_tmp;
            JL_encryption(this->sk, this->pk, e.weight, data_tmp.weight);
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



Client::Client() : graph(), D_pv(), D_e(), D_cv()
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