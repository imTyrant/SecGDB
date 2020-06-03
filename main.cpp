#include <iostream>
#include <fstream>
#include <chrono>
#include <boost/algorithm/string.hpp>
#include <gmpxx.h>
#include <openssl/conf.h>
#include <string>
#include <unordered_map>
#include <thread>

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
#include "network.hpp"

#include "mpc.hpp"
#include "io.hpp"

using namespace std;
namespace asio = boost::asio;
using boost::asio::ip::tcp;
namespace fs = boost::filesystem;

/*
 * For dbg
 */
void log_memory(const void* ptr, size_t size)
{
    BIO_dump_fp(stdout, (char*)ptr, size);
}

#if SEC_GDB_DBG
Client dbg_client;
SK g_sk;
PK g_pk;
#endif

void init_global_key(const char* keydir)
{
#if SEC_GDB_DBG
    fs::path outdir(keydir);
    load_sk((outdir.remove_trailing_separator() / "sk.json").string(), g_sk);
    load_pk((outdir.remove_trailing_separator() / "pk.json").string(), g_pk);
#endif
}

void init_dbg_client(const char* outputdir)
{
#if SEC_GDB_DBG
    fs::path outdir(outputdir);
    dbg_client.read_pk((outdir.remove_trailing_separator() / "pk.json").string());
    dbg_client.read_sk((outdir.remove_trailing_separator() / "sk.json").string());
#endif
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

size_t g_ivs_counter = 0;
double g_ivs_time_cost = 0.0;

size_t g_protocol_ctr = 0;

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
    fs::path outdir(args["outdir"].as<string>());

    Client client;

    int scaler=0;
    if (args["scale"].as<bool>())
    {
        scaler = SCALE_SHIFT_P;
    }

    auto enc_start = chrono::high_resolution_clock::now();
    client.enc_graph(args["infile"].as<string>(), scaler);
    auto enc_end = chrono::high_resolution_clock::now();

    cout << chrono::duration<double>(enc_end-enc_start).count() << endl;

    save_pk((outdir.remove_trailing_separator() / "pk.json"), client.get_pk());
    save_sk((outdir.remove_trailing_separator() / "sk.json"), client.get_sk());

    save_Dv((outdir.remove_trailing_separator() / "dcv.bin"), client.get_Dcv());
    save_Dv((outdir.remove_trailing_separator() / "dpv.bin"), client.get_Dpv());
    save_De((outdir.remove_trailing_separator() / "de.bin"), client.get_De());
}

void query_flow(cxxopts::ParseResult& args)
{
    fs::path outdir(args["outdir"].as<string>());
    Client client;
    client.read_pk((outdir.remove_trailing_separator() / "pk.json").string());
    client.read_sk((outdir.remove_trailing_separator() / "sk.json").string());

    init_dbg_client(outdir.string().c_str());
    init_global_key(outdir.string().c_str());

    client.enc_graph(args["infile"].as<string>());
    asio::io_service service;
    tcp::endpoint ep(asio::ip::address::from_string(args["address"].as<string>()), args["port"].as<short>());
    tcp::socket sock(service);

    Server server(client.get_De(), client.get_pk(), sock, ep);
    Request reqs = client.give_request("0", "5");

    auto query_start = chrono::high_resolution_clock::now();
    mpz_class result_enc = server.query_flow(reqs.F_1_s, reqs.P_s, reqs.P_t, reqs.constrained_key, reqs.ctr);
    // mpz_class result_enc = server.query_dist(reqs.F_1_s, reqs.P_s, reqs.P_t, reqs.constrained_key, reqs.ctr);
    auto query_end = chrono::high_resolution_clock::now();

    cout << chrono::duration<double>(query_end - query_start).count() << endl;

    mpz_class enc;
    JL_decryption(client.get_sk(), client.get_pk(), result_enc, enc);
    cout << "The final result is: " << enc.get_str() << endl;
}

void query_dist(cxxopts::ParseResult& args)
{
    fs::path outdir(args["outdir"].as<string>());

    // Client
    Client client;
    client.read_pk((outdir.remove_trailing_separator() / "pk.json").string());
    client.read_sk((outdir.remove_trailing_separator() / "sk.json").string());

    init_dbg_client(outdir.string().c_str());
    init_global_key(outdir.string().c_str());

    client.enc_graph(args["infile"].as<string>());
    // for (auto it = client.get_graph().adjacency_list.begin(); it != client.get_graph().adjacency_list.end(); it++)
    // {
    //     cout << it->first.name << " ";
    //     for (auto each : it->second)
    //     {
    //         cout << each.weight << " ";
    //     }
    //     cout << "\n";
    // }
    
    asio::io_service service;
    tcp::endpoint ep(asio::ip::address::from_string(args["address"].as<string>()), args["port"].as<short>());
    tcp::socket sock(service);

    Server server(client.get_De(), client.get_pk(), sock, ep);
    Request reqs = client.give_request("0", "8");

    auto query_start = chrono::high_resolution_clock::now();
    mpz_class result_enc = server.query_dist(reqs.F_1_s, reqs.P_s, reqs.P_t, reqs.constrained_key, reqs.ctr);
    auto query_end = chrono::high_resolution_clock::now();

    cout << chrono::duration<double>(query_end - query_start).count() << endl;

    mpz_class enc;
    JL_decryption(client.get_sk(), client.get_pk(), result_enc, enc);
    cout << "The final result is: " << enc.get_str() << endl;
}

void page_rank(cxxopts::ParseResult& args)
{
    fs::path outdir(args["outdir"].as<string>());

    // Prepare for global parameters
    init_dbg_client(outdir.string().c_str());
    init_global_key(outdir.string().c_str());

    // Client
    Client client;
    client.read_pk((outdir.remove_trailing_separator() / "pk.json").string());
    client.read_sk((outdir.remove_trailing_separator() / "sk.json").string());

    int scaler=0;
    if (args["scale"].as<bool>())
    {
        scaler = SCALE_SHIFT_P;
    }
    client.enc_graph(args["infile"].as<string>(), scaler);

    // Server
    asio::io_service service;
    tcp::endpoint ep(asio::ip::address::from_string(args["address"].as<string>()), args["port"].as<short>());
    tcp::socket sock(service);
    Server server(client.get_De(), client.get_pk(), sock, ep);

    // Begin works
    Request reqs = client.give_request("0", "1");

    auto query_start = chrono::high_resolution_clock::now();
    auto result = server.page_rank(reqs.F_1_s, reqs.P_s, reqs.constrained_key, reqs.ctr, args["epoch"].as<int>());
    auto query_end = chrono::high_resolution_clock::now();

    cout << chrono::duration<double>(query_end - query_start).count() << endl;

    size_t base = 1 << scaler;
    for (auto it = client.get_graph().vertices.begin(); it != client.get_graph().vertices.end(); it ++)
    {
        mpz_class weight;
        JL_decryption(client.get_sk(), client.get_pk(), result[it->second], weight);

        cout << "V: " << it->first
             << " pr: " << float(weight.get_ui()) / float(base) << endl;
    }
}

void start_proxy(cxxopts::ParseResult& args)
{
    fs::path outdir(args["outdir"].as<string>());

    // Client
    Client client;
    client.read_pk((outdir.remove_trailing_separator() / "pk.json").string());
    client.read_sk((outdir.remove_trailing_separator() / "sk.json").string());

    client.load_dcv((outdir.remove_trailing_separator() / "dcv.bin").string());
    client.load_dpv((outdir.remove_trailing_separator() / "dpv.bin").string());
    client.load_de((outdir.remove_trailing_separator() / "de.bin").string());

    asio::io_service service;
    tcp::acceptor acceptor(service, tcp::endpoint(tcp::v4(), args["port"].as<short>()));
    Proxy proxy(client.get_Dpv(), client.get_pk(), client.get_sk().jl_sk, acceptor, service);
    proxy.accept();
}

void simple_server(cxxopts::ParseResult& args)
{
    string address = args["address"].as<string>();
    short port = args["port"].as<short>();
    cout << "I'm server.." << endl;
    boost::asio::io_service service;
    boost::asio::ip::tcp::acceptor acc(service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port));
    PK pk;
    SK sk;

    load_pk(string("exp1/pk.json"), pk);
    load_sk(string("exp1/sk.json"), sk);
    for(;;)
    {
        boost::asio::ip::tcp::socket clt(service);
        acc.accept(clt);
        cout << "Client connected.." << endl;
        clt.set_option(boost::asio::ip::tcp::no_delay(true));
        while(true)
        {
            try
            {
                // secure_multiply_remote(pk.jl_pk, sk.jl_sk, clt);
                secure_inverse_remote(pk.jl_pk, sk.jl_sk, clt);
            }
            catch(const std::exception& e)
            {
                std::cerr << e.what() << '\n';
                break;
            }
            
        }
        clt.close();
    }
}

void simple_client(cxxopts::ParseResult& args)
{
    string address = args["address"].as<string>();
    short port = args["port"].as<short>();
    cout << "I'm client.." << endl;
    boost::asio::io_service service;
    boost::asio::ip::tcp::socket sock(service);
    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::address::from_string(address), port);
    sock.connect(ep);
    sock.set_option(boost::asio::ip::tcp::no_delay(true));

    PK pk;
    SK sk;

    load_pk(string("exp1/pk.json"), pk);
    load_sk(string("exp1/sk.json"), sk);

    init_global_key("exp1");

    while (true)
    {
        try
        {
            boost::system::error_code ec;
            float input;
            cin >> input;
            size_t base = (1 << SCALE_SHIFT_P);
            size_t tmp = (size_t)(input * base);
            
            mpz_class input_enc;
            JL_encryption(pk, tmp, input_enc);

            mpz_class out_enc = secure_inverse(pk.jl_pk, input_enc, sock, SCALE_SHIFT_P);

            mpz_class mbase(base);  
            mpz_class mtwo(2 * base);
            mpz_class rtn(2);
            mpz_class ii(tmp);
            // long long rtn = 1;//(float(base) * 0.001);
            // long long two = 2 * base;
            // for (int i = 0; i < INVERSE_ITERS; i ++)
            // {
            //     // int tmp1 = rtn * tmp;
            //     // int tmp2 = 2 * base - tmp1;
            //     // rtn *= tmp2;
            //     rtn = rtn * (mtwo - (rtn * ii / mbase)) / mbase;
            // }

            mpz_class output;
            JL_decryption(sk, pk, out_enc, output);
            
            cout << output.get_str() << " " << rtn.get_str() << endl;
            cout << float(output.get_ui()) / float(base) << " " << (1 / input) << endl;

        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            break;
        }
    }
    cout << "Quiting.." << endl;
}

/* Experiments regester. */
unordered_map<string, void (*) (cxxopts::ParseResult&)> Experiments({
    {"simple_client", simple_client},
    {"simple_server", simple_server},
    {"simple_test", simple_test},
    {"enc_graph", enc_graph},
    {"start_proxy", start_proxy},
    {"query_dist", query_dist},
    {"query_flow", query_flow},
    {"page_rank", page_rank}
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
        ("a,address", "IP address for the proxy", cxxopts::value<string>()->default_value("127.0.0.1"))
        ("p,port", "Port for the proxy", cxxopts::value<short>()->default_value("23333"))
        ("party", "Specify current party", cxxopts::value<string>())
        ("epoch", "Epoch for the page rank", cxxopts::value<int>()->default_value("50"))
        ("scale", "Scale up graph weight", cxxopts::value<bool>()->default_value("false"))
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