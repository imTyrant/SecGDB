#include <iostream>
#include <fstream>

#include <gmpxx.h>

#include "global.h"

#include "client.hpp"
#include "server.hpp"
#include "ggm.h"
#include "crypto_stuff.hpp"
#include "graph.hpp"
#include "data_structures.hpp"

#ifdef SEC_GDB_SIMPLE_MODE
#include "sec_compare.hpp"
#endif

#include <openssl/conf.h>

using namespace std;

void log_memory(const void* ptr, size_t size)
{
    BIO_dump_fp(stdout, (char*)ptr, size);
}


#ifdef SEC_GDB_SIMPLE_MODE
    Client g_client;
    size_t g_compare_counter = 0;
#endif

int main(int argc, char* argv[])
{
    if (argc < 4)
    {   
        cout << "Usage:\n";
        cout << "\tEXE [FILE] | [SRC] | [DEST]\n";
        return EXIT_SUCCESS;
    }
    Request req;
#ifdef SEC_GDB_SIMPLE_MODE
    g_client.enc_graph(argv[1]);
    Server server(g_client.get_De(), g_client.get_pk());
    req = g_client.give_request(argv[2], argv[3]);
#else 
    Client client;
#endif

    if (req.validity)
    {
        // mpz_class dist_result = server.query_dist(req.F_1_s, req.P_s, req.P_t, req.constrained_key, req.ctr);
        // mpz_class dis_out;
        // JL_decryption(g_client.get_sk(), g_client.get_pk(), dist_result, dis_out);
        // cout << "========================DIST========================\n";
        // cout << "Distance: " << dis_out.get_str() << "\n";
        // cout << "Total compare times " << g_compare_counter << "\n";

        mpz_class flow_result = server.query_flow(req.F_1_s, req.P_s, req.P_t, req.constrained_key, req.ctr);
        mpz_class flow_out;
        JL_decryption(g_client.get_sk(), g_client.get_pk(), flow_result, flow_out);
        cout << "========================FLOW========================\n";
        cout << "Flow: " << flow_out.get_str() << "\n";
        cout << "Total compare times " << g_compare_counter << "\n";

        ggm_free_constrain(&req.constrained_key);
    }
    else
    {
        cout << "Wrong request\n";
    }
    /*
    size_t correct = 0;
    size_t error = 0;

    for (int i = 0; i < 1000; i++)
    {
        mpz_class left;
        mpz_class right;

        unsigned char rand_buff[KEY_SIZE] = {0};

        mpz_class seed;

        ifstream in_file("/dev/urandom");

        if (!in_file.fail())
        {
            in_file.getline((char *)rand_buff, KEY_SIZE);
            in_file.close();
        }
        else
        {
            cout << "Fail to open random source\n";
            for (int i = 0; i < KEY_SIZE; i++)
            {
                rand_buff[i] = '0' + (char)i;
            }
        }

        mpz_import(seed.get_mpz_t(), sizeof(rand_buff), 1, sizeof(rand_buff[0]), 0, 0, rand_buff);
        gmp_randstate_t rand_st;
        gmp_randinit_default(rand_st);
        gmp_randseed(rand_st, seed.get_mpz_t());

        // Subtract 1 is for preventing overflow
        mpz_urandomb(left.get_mpz_t(), rand_st, sizeof(long long) * 8  - 2);
        mpz_urandomb(right.get_mpz_t(), rand_st, sizeof(long long) * 8  - 2);

        gmp_randclear(rand_st);

        mpz_class blined_left;
        mpz_class blined_right;
        JL_encryption(g_client.get_pk(), left, blined_left);
        JL_encryption(g_client.get_pk(), right, blined_right);

        int supposed_result;
        if (left > right) {supposed_result = 1;}
        else if (left == right) {supposed_result = 0;}
        else {supposed_result = -1;}

        cout << "src l: " << left.get_str();
        cout << " \tsrc r: " << right.get_str();
        cout << " \t supr" << supposed_result << endl;

        // cout << "bld_l: " << blined_left.get_str();
        // cout << " \tbld_r: " << blined_right.get_str() << endl;

        // mpz_class plain_l;
        // mpz_class plain_r;

        // JL_decryption(g_client.get_sk(), g_client.get_pk(), blined_left, plain_l);
        // JL_decryption(g_client.get_sk(), g_client.get_pk(), blined_right, plain_r);

        // cout << "ubld_l: " << plain_l.get_str();
        // cout << " \tubld_r: " << plain_r.get_str() << endl;

        cout << "#" << g_compare_counter << "\t";
        if (supposed_result == secure_compare(g_client.get_pk(), blined_left, blined_right))
        {
            cout << "Correct";
            correct ++;
        }
        else
        {
            cout << "Wrong";
            error ++;
        }
        
        cout << " \t correct rate: " << double(correct) / double(correct + error);
        cout << " \t error rate: " << double(error) / double(correct + error) << "\n";

        // cout << "src l: " << left.get_str();
        // cout << " \tsrc r: " << right.get_str() << endl;
        // cout << "_________________________________________________\n";
    }
    */
   return EXIT_SUCCESS;
}