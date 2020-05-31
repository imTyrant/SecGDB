#include <iostream>
#include <fstream>
#include <chrono>
#include <boost/algorithm/string.hpp>
#include <gmpxx.h>
#include <openssl/conf.h>
#include <string>
#include <unordered_map>

#include <boost/filesystem.hpp>
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

#include "mpc.hpp"
#include "io.hpp"

using namespace std;
using namespace boost::filesystem;
/*
 * For dbg
 */
void log_memory(const void* ptr, size_t size)
{
    BIO_dump_fp(stdout, (char*)ptr, size);
}

/* Simple mode */
#ifdef SEC_GDB_SIMPLE_MODE
boost::asio::io_service service;
boost::asio::ip::tcp::acceptor acc(service, boost::asio::ip::tcp::v4(), PORT);
Proxy g_proxy(acc, service);
Client g_client;
#endif // SEC_GDB_SIMPLE_MODE

/* global parameters */
double g_c_update_clt = 0.0;
double g_c_update_srv = 0.0;
double g_c_update_prxy = 0.0;

size_t g_s_cache_size = 0;
size_t g_s_use_cache = 0;
size_t g_fh_compare_time = 0;

size_t g_compare_counter = 0;
double g_compare_time_cost = 0.0;

size_t g_mul_counter = 0;
double g_mul_time_cost = 0.0;

void simple_test(cxxopts::ParseResult& args)
{
#ifdef SEC_GDB_SIMPLE_MODE
    g_client.enc_graph(args["input"].as<string>());
    g_proxy.set_params(g_client.get_Dpv(), g_client.get_pk(), g_client.get_sk().jl_sk);
    Server server(g_client.get_De(), g_client.get_pk());
#else
    cout << "Simple mode is not enable, quit." << endl;
#endif
}

void enc_graph(cxxopts::ParseResult& args)
{
    path outdir(args["outdir"].as<string>());

    Client client;
    auto enc_start = chrono::high_resolution_clock::now();
    client.enc_graph(args["input"].as<string>());
    auto enc_end = chrono::high_resolution_clock::now();

    save_pk((outdir.remove_trailing_separator() / "pk.json"), client.get_pk());
    save_sk((outdir.remove_trailing_separator() / "sk.json"), client.get_sk());

    save_Dv((outdir.remove_trailing_separator() / "dcv.bin"), client.get_Dcv());
    save_Dv((outdir.remove_trailing_separator() / "dpv.bin"), client.get_Dpv());
    save_De((outdir.remove_trailing_separator() / "de.bin"), client.get_De());
}

/* Experiments regester. */
unordered_map<string, void (*) (cxxopts::ParseResult&)> Experiments({
    {"simple_test", simple_test},
    {"enc_graph", enc_graph}
});

/* Main */
int main(int argc, char *argv[])
{
    cxxopts::Options options("GraphShield");
    options.add_options()
        ("e,exp", "Name an experiment", cxxopts::value<string>())
        ("i,infile", "Input graph file", cxxopts::value<string>())
        ("o,outdir", "Directory where data to be saved", cxxopts::value<string>())
        ("l,log", "File for experiment results", cxxopts::value<string>()->default_value("./result.json"))
        ("party", "Specify current party", cxxopts::value<string>())
        ("a,address", "IP address for the proxy", cxxopts::value<string>()->default_value("127.0.0.1"))
        ("p,port", "Port for the proxy", cxxopts::value<short>()->default_value("23333"))
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
        if (Experiments.find(exp) != Experiments.end())
        {
            Experiments[exp](args);
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
