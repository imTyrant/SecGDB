#include <iostream>
#include <fstream>
#include <chrono>

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
    double g_total_compare_time = 0.0;
    double g_total_wait_time = 0.0;
#endif
/*
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
    auto enc_begin_time = chrono::high_resolution_clock::now();
    g_client.enc_graph(argv[1]);
    auto enc_finish_time = chrono::high_resolution_clock::now();
    chrono::duration<double> enc_time = enc_finish_time - enc_begin_time;
    cout << "Encrytion Graph time: " << enc_time.count() << "\n";

    Server server(g_client.get_De(), g_client.get_pk());
    auto demand_begin_time = chrono::high_resolution_clock::now();
    req = g_client.give_request(argv[2], argv[3]);
    auto demand_finish_time = chrono::high_resolution_clock::now();
    chrono::duration<double> demand_time = demand_finish_time - demand_begin_time;
    cout << "Generate query time: " << demand_time.count() << "\n";
#else 
    Client client;
#endif

    if (req.validity)
    {
        // auto query_begin_time = chrono::high_resolution_clock::now();
        // mpz_class dist_result = server.query_dist(req.F_1_s, req.P_s, req.P_t, req.constrained_key, req.ctr);
        // mpz_class dis_out;
        // JL_decryption(g_client.get_sk(), g_client.get_pk(), dist_result, dis_out);
        // auto query_finish_time = chrono::high_resolution_clock::now();
        // chrono::duration<double> query_time = query_finish_time - query_begin_time;

        // cout << "========================DIST========================\n";
        // cout << "Distance: " << dis_out.get_str() << "\n";
        // cout << "Query time consumption: " << query_time.count() << "\n";
        // cout << "Total compare: " << g_compare_counter << "\n";
        // cout << "Total wait time: " << g_total_wait_time << "\n";
        // cout << "Total compare time: " << g_total_compare_time << "\n";

        auto query_begin_time = chrono::high_resolution_clock::now();
        mpz_class flow_result = server.query_flow(req.F_1_s, req.P_s, req.P_t, req.constrained_key, req.ctr);
        mpz_class flow_out;
        JL_decryption(g_client.get_sk(), g_client.get_pk(), flow_result, flow_out);
        auto query_finish_time = chrono::high_resolution_clock::now();
        chrono::duration<double> query_time = query_finish_time - query_begin_time;
        cout << "========================FLOW========================\n";
        cout << "Flow: " << flow_out.get_str() << "\n";
        cout << "Query time consumption: " << query_time.count() << "\n";
        cout << "Total compare: " << g_compare_counter << "\n";
        cout << "Total wait time: " << g_total_wait_time << "\n";
        cout << "Total compare time: " << g_total_compare_time << "\n";

        ggm_free_constrain(&req.constrained_key);
    }
    else
    {
        cout << "Wrong request\n";
    }
    // / *
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
    //* /
   return EXIT_SUCCESS;
}
*/

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        cout << "Usage: \n";
        cout << "\t EXE [FILE]\n";
        return EXIT_SUCCESS;
    }

    cout << "<file>\n";
    cout << "<name>" << argv[1] << "</name>";
    for (int i = 0; i < 2; i++)
    {
        cout << "<redo>\n";

        
        auto enc_begin_time = chrono::high_resolution_clock::now();
        g_client.enc_graph(argv[1]);
        auto enc_finish_time = chrono::high_resolution_clock::now();
        chrono::duration<double> enc_time = enc_finish_time - enc_begin_time;
        cout << "<enc_graph>" << enc_time.count() << "</enc_graph>\n";

        Server server(g_client.get_De(), g_client.get_pk());

        Request req;

        cout << "<req_test>\n";

        chrono::duration<double> demand_time;
        string src;
        string dest;
        do
        {
            srand(time(NULL));
            src = to_string(rand() % g_client.get_graph().num_vertices);
            dest = to_string(rand() % g_client.get_graph().num_vertices);

            auto demand_begin_time = chrono::high_resolution_clock::now();
            req = g_client.give_request(src, dest);
            auto demand_finish_time = chrono::high_resolution_clock::now();
            demand_time = demand_finish_time - demand_begin_time;

        } while (!req.validity);
        
        cout << "<req_detail>\n";
        cout << "<src>" << src << "</src>\n";
        cout << "<dest>" << dest << "</dest>\n";
        cout <<  "</req_detail>\n";
        cout << "<give_request>" << demand_time.count() << "</give_request>\n";

        for (int j = 0; j < 2; j++)
        {
            auto dist_query_begin_time = chrono::high_resolution_clock::now();
            mpz_class dist_result = server.query_dist(req.F_1_s, req.P_s, req.P_t, req.constrained_key, req.ctr);
            auto dist_query_finish_time = chrono::high_resolution_clock::now();
            chrono::duration<double> dist_query_time = dist_query_finish_time - dist_query_begin_time;
            
            auto dist_get_begin_time = chrono::high_resolution_clock::now();
            mpz_class dis_out;
            JL_decryption(g_client.get_sk(), g_client.get_pk(), dist_result, dis_out);
            auto dist_get_finish_time = chrono::high_resolution_clock::now();
            chrono::duration<double> dist_get_time = dist_get_finish_time - dist_get_begin_time;
            

            cout << "<dist_query>\n";
                cout << "<distance>" << dis_out.get_str() << "</distance>\n";
                cout << "<query_time>" << dist_query_time.count() << "</query_time>\n";
                cout << "<get_time>" << dist_get_time.count() << "</get_time>\n";
                cout << "<compare>" << g_compare_counter << "</compare>\n";
                cout << "<wait_time>" << g_total_wait_time << "</wait_time>\n";
                cout << "<compare_time>" << g_total_compare_time << "</compare_time>\n";
            cout << "</dist_query>\n";

            g_compare_counter = 0;
            g_total_wait_time = 0.0;
            g_total_compare_time = 0.0;

            auto flow_query_begin_time = chrono::high_resolution_clock::now();
            mpz_class flow_result = server.query_flow(req.F_1_s, req.P_s, req.P_t, req.constrained_key, req.ctr);
            auto flow_query_finish_time = chrono::high_resolution_clock::now();
            chrono::duration<double> flow_query_time = flow_query_finish_time - flow_query_begin_time;
            
            auto flow_get_begin_time = chrono::high_resolution_clock::now();
            mpz_class flow_out;
            JL_decryption(g_client.get_sk(), g_client.get_pk(), flow_result, flow_out);
            auto flow_get_finish_time = chrono::high_resolution_clock::now();
            chrono::duration<double> flow_get_time = flow_get_finish_time - flow_get_begin_time;
            
            cout << "<flow_query>\n";
                cout << "<flow>" << flow_out.get_str() << "</flow>\n";
                cout << "<query_time>" << flow_query_time.count() << "</query_time>\n";
                cout << "<get_time>" << flow_get_time.count() << "</get_time>\n";
                cout << "<compare>" << g_compare_counter << "</compare>\n";
                cout << "<wait_time>" << g_total_wait_time << "</wait_time>\n";
                cout << "<compare_time>" << g_total_compare_time << "</compare_time>\n";
            cout << "</flow_query>\n";
        }
        ggm_free_constrain(&req.constrained_key);

        cout << "</req_test>\n";

        cout << "</redo>\n";
    }

    cout << "</file>\n";

    return EXIT_SUCCESS;
}
