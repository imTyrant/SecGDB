#include <iostream>
#include <fstream>
#include <chrono>
#include <boost/algorithm/string.hpp>

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

size_t g_fh_compare_time = 0;

double g_c_update_clt;
double g_c_update_srv;
double g_c_update_prxy;

int g_s_ttt = 0;
int g_s_cccddd = 0;
int g_s_total_cnttt = 0;

size_t g_s_use_cache = 0;
size_t g_s_cache_size = 0;
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
    if (argc < 3)
    {
        cout << "Usage: \n";
        cout << "\t EXE [IN_FILE] [OUT_FILE]\n";
        return EXIT_SUCCESS;
    }

    vector<string> all_request;
    if (argc == 4)
    {
        ifstream request_in(argv[3], std::ifstream::in);
        string line;

        if (request_in.fail())
        {
            std::cout << "Read graph file failed!\n";
        }

        while (getline(request_in, line))
        {
            all_request.push_back(line);
        }

        request_in.close();
    }
    ofstream out_file(argv[2], ios::out);
    if (!out_file)
    {
        cout << "Open File failed!\n";
        return EXIT_FAILURE;
    }

    cout << "File: " << argv[1] << "\n";

    out_file << "<file>\n";
    out_file << "<name>" << argv[1] << "</name>\n";

    auto enc_begin_time = chrono::high_resolution_clock::now();
    g_client.enc_graph(argv[1]);
    auto enc_finish_time = chrono::high_resolution_clock::now();
    chrono::duration<double> enc_time = enc_finish_time - enc_begin_time;

    out_file << "\t<enc_graph>" << enc_time.count() << "</enc_graph>\n" << endl;

    Server server(g_client.get_De(), g_client.get_pk());

    srand(time(NULL));

    // for (int i = 0; i < 100; i++)
    // while(1)
    for (int i =0; i < all_request.size(); i++)
    {
        g_fh_compare_time = 0;
        g_compare_counter = 0;
        g_total_wait_time = 0.0;
        g_total_compare_time = 0.0;

        out_file << "<redo>\n";

        Request req;

        out_file << "\t<req_test>\n";

        chrono::duration<double> demand_time;
        string src;
        string dest;
        do
        {
            vector<string> strs;
            boost::split(strs, all_request[i], boost::is_any_of(" "));
            src = strs[0];
            dest = strs[1];

            // cout << "Input src and dest: \n";
            // cin >> src;
            // cin >> dest;
            //src = to_string(rand() % g_client.get_graph().num_vertices);
            //dest = to_string(rand() % g_client.get_graph().num_vertices);

            auto demand_begin_time = chrono::high_resolution_clock::now();
            req = g_client.give_request(src, dest);
            auto demand_finish_time = chrono::high_resolution_clock::now();
            demand_time = demand_finish_time - demand_begin_time;

        } while (!req.validity);

        cout << "==================================================\n";
        cout << "Request: " << src << " -> " << dest << "\n\n";

        out_file << "\t\t<req_detail>\n";
        out_file << "\t\t\t<src>" << src << "</src>\n";
        out_file << "\t\t\t<dest>" << dest << "</dest>\n";
        out_file << "\t\t</req_detail>\n";
        out_file << "\t\t<give_request>" << demand_time.count() << "</give_request>\n"
                 << endl;

        auto dist_query_begin_time = chrono::high_resolution_clock::now();
        mpz_class dist_result = server.query_dist(req.F_1_s, req.P_s, req.P_t, req.constrained_key, req.ctr);
        auto dist_query_finish_time = chrono::high_resolution_clock::now();
        chrono::duration<double> dist_query_time = dist_query_finish_time - dist_query_begin_time;

        auto dist_get_begin_time = chrono::high_resolution_clock::now();
        mpz_class dis_out;
        JL_decryption(g_client.get_sk(), g_client.get_pk(), dist_result, dis_out);
        auto dist_get_finish_time = chrono::high_resolution_clock::now();
        chrono::duration<double> dist_get_time = dist_get_finish_time - dist_get_begin_time;

        cout << "Distance: " << dis_out.get_str() << "\n";
        cout << "Query time: " << dist_query_time.count() << "\n";
        cout << "Extract heap : " << g_s_ttt << "\n";
        cout << "Total out degree: " << g_s_total_cnttt << "\n";
        cout << "Total running round: " << g_s_cccddd << "\n";
        cout << "FH compare time: " << g_fh_compare_time << "\n";
        cout << "Compare times:   " << g_compare_counter << "\n\n";


        out_file << "\t\t<dist_query>\n";
        out_file << "\t\t\t<distance>" << dis_out.get_str() << "</distance>\n";
        out_file << "\t\t\t<query_time>" << dist_query_time.count() << "</query_time>\n";
        out_file << "\t\t\t<get_time>" << dist_get_time.count() << "</get_time>\n";
        out_file << "\t\t\t<compare>" << g_compare_counter << "</compare>\n";
        out_file << "\t\t\t<wait_time>" << g_total_wait_time << "</wait_time>\n";
        out_file << "\t\t\t<compare_time>" << g_total_compare_time << "</compare_time>\n";
        out_file << "\t\t</dist_query>\n"
                 << endl;

        // g_compare_counter = 0;
        // g_total_wait_time = 0.0;
        // g_total_compare_time = 0.0;

        // auto flow_query_begin_time = chrono::high_resolution_clock::now();
        // mpz_class flow_result = server.query_flow(req.F_1_s, req.P_s, req.P_t, req.constrained_key, req.ctr);
        // auto flow_query_finish_time = chrono::high_resolution_clock::now();
        // chrono::duration<double> flow_query_time = flow_query_finish_time - flow_query_begin_time;

        // auto flow_get_begin_time = chrono::high_resolution_clock::now();
        // mpz_class flow_out;
        // JL_decryption(g_client.get_sk(), g_client.get_pk(), flow_result, flow_out);
        // auto flow_get_finish_time = chrono::high_resolution_clock::now();
        // chrono::duration<double> flow_get_time = flow_get_finish_time - flow_get_begin_time;

        // cout << "Flow: " << flow_out.get_str() << "\n";
        // cout << "Total time: " << flow_query_time.count() << "\n";
        // cout << "Compare Times: " << g_compare_counter << "\n\n";

        // out_file << "\t\t<flow_query>\n";
        // out_file << "\t\t\t<flow>" << flow_out.get_str() << "</flow>\n";
        // out_file << "\t\t\t<query_time>" << flow_query_time.count() << "</query_time>\n";
        // out_file << "\t\t\t<get_time>" << flow_get_time.count() << "</get_time>\n";
        // out_file << "\t\t\t<compare>" << g_compare_counter << "</compare>\n";
        // out_file << "\t\t\t<wait_time>" << g_total_wait_time << "</wait_time>\n";
        // out_file << "\t\t\t<compare_time>" << g_total_compare_time << "</compare_time>\n";
        // out_file << "\t\t</flow_query>\n"
        //          << endl;

        ggm_free_constrain(&req.constrained_key);

        out_file << "\t</req_test>\n";
        out_file << "</redo>\n"
                 << endl;

        sleep(1);
    }

    out_file << "</file>\n" << endl;
    out_file.close();

    return EXIT_SUCCESS;
}


/*
int main(int argc, char* argv[])
{
    auto enc_time_begin = chrono::high_resolution_clock::now();
    g_client.enc_graph(argv[1]);
    auto enc_time_end = chrono::high_resolution_clock::now();
    chrono::duration<double> enc_time = enc_time_end - enc_time_begin;

    cout << "File: " << argv[1] << "\n";
    cout << "Enc: " << enc_time.count() << "\n";
    ofstream out_file(argv[2], ios::out);
    if (!out_file)
    {
        cout << "Cannot open output file!\n";
        return EXIT_FAILURE;
    }

    srand(time(NULL));
    for (int i = 0; i < 20; i++)
    {
        g_c_update_clt = 0;
        g_c_update_srv = 0;
        g_c_update_prxy = 0;

        string src;
        string dest;
        do
        {
            src = to_string(rand() % 100 + g_client.get_graph().num_vertices);
            dest = to_string(rand() % 100 + g_client.get_graph().num_vertices);
        } while (src != dest);
        size_t weight = rand() % 100;
        g_client.update_graph(src, dest, weight, SEC_GDB_UPDATE_OP_ADD);

        cout << "Clinet: " << g_c_update_clt << "\n";
        cout << "Proxy: " << g_c_update_prxy << "\n";
        cout << "Server: " << g_c_update_srv << "\n\n";

        out_file << "Clinet: " << g_c_update_clt << "\n";
        out_file << "Proxy: " << g_c_update_prxy << "\n";
        out_file << "Server: " << g_c_update_srv << "\n";
        out_file << "==================================" << endl;
    }

    if (argc == 4)
    {
        string dcv(argv[3]);
        string dpv(argv[3]);
        string de(argv[3]);
        dcv += "/dcv";
        dpv += "/dpv";
        de += "/de";

        cout << "Writing D_cv to " << dcv << "\n";
        g_client.store_dcv(dcv);
        cout << "Writing D_pv to " << dpv << "\n";
        g_client.store_dpv(dpv);
        cout << "Writing D_e to " << de << "\n";
        g_client.store_de(de);
    }
    out_file.close();
    return EXIT_SUCCESS;
}
*/


/*
int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        cout << "Usage: \n";
        cout << "\t EXE [IN_FILE] [OUT_FILE]\n";
        return EXIT_SUCCESS;
    }
    ofstream out_file(argv[2], ios::out);
    if (!out_file)
    {
        cout << "Open File failed!\n";
        return EXIT_FAILURE;
    }

    cout << "File: " << argv[1] << "\n";

    g_client.enc_graph(argv[1]);

    Server server(g_client.get_De(), g_client.get_pk());

    srand(time(NULL));

    int count_2 = 6;
    int count_3 = 2;
    int count_4 = 2;

    for (int i = 0; i < 100; i++)
    {
        bool finded = false;

        g_fh_compare_time = 0;
        g_compare_counter = 0;
        g_total_wait_time = 0.0;
        g_total_compare_time = 0.0;

        Request req;

        string src;
        string dest;
        do
        {
            src = to_string(rand() % g_client.get_graph().num_vertices);
            dest = to_string(rand() % g_client.get_graph().num_vertices);
            req = g_client.give_request(src, dest);
        } while (!req.validity);

        cout << "==================================================\n";
        cout << "Request: " << src << " -> " << dest << "\n";

        

        mpz_class dist_result = server.query_dist(req.F_1_s, req.P_s, req.P_t, req.constrained_key, req.ctr);

        mpz_class dis_out;
        JL_decryption(g_client.get_sk(), g_client.get_pk(), dist_result, dis_out);
        
        size_t distance = dis_out.get_ui();

        cout << "Distance: " << dis_out.get_str() << "\n";
        cout << "Extract heap : " << g_s_ttt << "\n";
        cout << "Total out degree: " << g_s_total_cnttt << "\n";
        cout << "Total running round: " << g_s_cccddd << "\n";
        cout << "FH compare time: " << g_fh_compare_time << "\n";
        cout << "Compare times:   " << g_compare_counter << "\n\n";

        switch (distance)
        {
            case 2:
                count_2--;
                finded = true;
                break;
            case 3:
                count_3--;
                finded = true;
                break;
            case 4:
                count_4--;
                finded = true;
                break;
            default:
                break;
        }

        if (finded)
        {
            out_file << "==================================================\n";
            out_file << "Request: " << src << " -> " << dest << "\n";
            out_file << "Distance: " << dis_out.get_str() << "\n";
            out_file << "Extract heap : " << g_s_ttt << "\n";
            out_file << "Total out degree: " << g_s_total_cnttt << "\n";
            out_file << "Total running round: " << g_s_cccddd << "\n";
            out_file << "FH compare time: " << g_fh_compare_time << "\n";
            out_file << "Compare times:   " << g_compare_counter << "\n"
                     << endl;
        }

        if (count_2 < 0 && count_3 < 0 && count_4 < 0)
        {
            ggm_free_constrain(&req.constrained_key);
            break;    
        }

        ggm_free_constrain(&req.constrained_key);

        sleep(1);
    }

    out_file.close();

    return EXIT_SUCCESS;
}
*/
/* 
int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        cout << "Usage: \n";
        cout << "\t EXE [IN_FILE] [OUT_FILE]\n";
        return EXIT_SUCCESS;
    }
    ofstream out_file(argv[2], ios::out);
    if (!out_file)
    {
        cout << "Open File failed!\n";
        return EXIT_FAILURE;
    }

    cout << "File: " << argv[1] << "\n";

    g_client.enc_graph(argv[1]);


    for (int i = 0; i < 50; i++)
    {
        Request req;

        string src;
        string dest;
        do
        {
            src = to_string(rand() % g_client.get_graph().num_vertices);
            dest = to_string(rand() % g_client.get_graph().num_vertices);
            req = g_client.give_request(src, dest);
        } while (!req.validity);

        cout << "==================================================\n";
        cout << "Request: " << src << " -> " << dest << "\n";

        int ck_cnt = 0;
        Constrain* tmp = &req.constrained_key;
        while (tmp != NULL)
        {
            ck_cnt++;
            tmp = tmp->next;
        }
        cout << "Total constrained key: " << ck_cnt << "\n";
        cout << "Size : " << KEY_SIZE * 3 + ck_cnt * (KEY_SIZE + sizeof(int)) + sizeof(size_t) << "\n";

        out_file << "==================================================\n";
        out_file << src << ":";
        out_file << KEY_SIZE * 3 + ck_cnt * (KEY_SIZE + sizeof(int)) + sizeof(size_t) << endl;

        ggm_free_constrain(&req.constrained_key);

        sleep(1);
    }

    out_file.close();

    return EXIT_SUCCESS;
}
 */
/*
int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        cout << "Usage: \n";
        cout << "\t EXE [IN_FILE] [OUT_FILE]\n";
        return EXIT_SUCCESS;
    }

    ofstream out_file(argv[2], ios::out);
    if (!out_file)
    {
        cout << "Open File failed!\n";
        return EXIT_FAILURE;
    }

    cout << "File: " << argv[1] << "\n";

    g_client.enc_graph(argv[1]);

    Server server(g_client.get_De(), g_client.get_pk());

    srand(time(NULL));

    for (int i = 1; i < 10001; i++)
    {
        g_fh_compare_time = 0;
        g_compare_counter = 0;
        g_total_wait_time = 0.0;
        g_total_compare_time = 0.0;

        Request req;

        chrono::duration<double> demand_time;
        string src;
        string dest;
        do
        {
            // cout << "Input src and dest: \n";
            // cin >> src;
            // cin >> dest;
            src = to_string(rand() % g_client.get_graph().num_vertices);
            dest = to_string(rand() % g_client.get_graph().num_vertices);

            req = g_client.give_request(src, dest);

        } while (!req.validity);

        cout << "==================================================\n";
        cout << "Request: " << src << " -> " << dest << "\n\n";

        mpz_class dist_result = server.query_dist(req.F_1_s, req.P_s, req.P_t, req.constrained_key, req.ctr);

        mpz_class dis_out;
        JL_decryption(g_client.get_sk(), g_client.get_pk(), dist_result, dis_out);

        cout << "Distance: " << dis_out.get_str() << "\n";
        cout << "FH compare time: " << g_fh_compare_time << "\n";
        cout << "Compare times:   " << g_compare_counter << "\n";
        cout << "Ratio: " << (double(i) - double(g_s_use_cache)) / double(i) << "\n";
        cout << "Size: " << g_s_cache_size << "\n";

        out_file << "==================================================\n";
        out_file << "#" << i << "\n";
        out_file << "Distance: " << dis_out.get_str() << "\n";
        out_file << "Ratio: " << (double(i) - double(g_s_use_cache)) / double(i) << "\n";
        out_file << "Size: " << g_s_cache_size << "\n"
                 << endl;

        ggm_free_constrain(&req.constrained_key);

        sleep(1);
    }

    out_file.close();

    return EXIT_SUCCESS;
}
*/