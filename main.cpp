#include <iostream>
#include <fstream>
#include <chrono>
#include <boost/algorithm/string.hpp>
#include <gmpxx.h>
#include <openssl/conf.h>
#include <string>
#include <unordered_map>

#include "cxxopts.hpp"
#include "nlohmann/json.hpp"

#include "global.h"

#include "client.hpp"
#include "server.hpp"
#include "proxy.hpp"

#include "ggm.h"
#include "crypto_stuff.hpp"
#include "graph.hpp"
#include "data_structures.hpp"

#ifdef SEC_GDB_SIMPLE_MODE
#include "sec_compare.hpp"
#endif

using namespace std;
/*
 * For dbg
 */
void log_memory(const void* ptr, size_t size)
{
    BIO_dump_fp(stdout, (char*)ptr, size);
}

/*
 * Simple case
 */
#ifdef SEC_GDB_SIMPLE_MODE
Proxy g_proxy;
Client g_client;
// local compare
size_t g_compare_counter = 0;
double g_total_compare_time = 0.0;
double g_total_wait_time = 0.0;
// locally update graph
double g_c_update_clt = 0.0;
double g_c_update_srv = 0.0;
double g_c_update_prxy = 0.0;
#endif

size_t g_s_cache_size = 0;
size_t g_s_use_cache = 0;
size_t g_fh_compare_time = 0;

void simple_test(cxxopts::ParseResult& args)
{
#ifdef SEC_GDB_SIMPLE_MODE
    g_client.enc_graph(args["input"].as<string>());
    g_proxy.set_params(g_client.get_Dpv(), g_client.get_pk());
    Server server(g_client.get_De(), g_client.get_pk());
#else
    cout << "Simple mode is not enable, quit." << endl;
#endif

}

/* 
 * Experiments regester.
 */
unordered_map<string, void (*) (cxxopts::ParseResult&)> EXPS({
    {"simple_test", simple_test},
});

/* 
 * Main
 */
int main(int argc, char *argv[])
{
    cxxopts::Options options("GraphShield");
    options.add_options()
        ("e,exp", "Name an experiment", cxxopts::value<string>())
        ("i,input", "Input graph file", cxxopts::value<string>())
        ("o,ouput", "Directory where data to be saved", cxxopts::value<string>())
        ("party", "Specify current party", cxxopts::value<string>())
        ("l,log", "File for experiment results", cxxopts::value<string>()->default_value("./result.json"))
        ("h,help", "Print usage")
        ;
    try
    {
        auto args = options.parse(argc, argv);
        if (args.count("help"))
        {
            cout << options.help() << endl;
            return EXIT_SUCCESS;
        }

        const string& exp = args["exp"].as<string>();
        if (EXPS.find(exp) != EXPS.end())
        {
            EXPS[exp](args);
        }
    }
    catch(const cxxopts::OptionException& e)
    {
        cout << options.help() << endl;
    }
    catch(const std::domain_error& e)
    {
        cout << options.help() << endl;
    }
    
    return EXIT_SUCCESS;
}
