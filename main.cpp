#include <iostream>
#include <fstream>
#include <chrono>
#include <boost/algorithm/string.hpp>
#include <gmpxx.h>
#include <openssl/conf.h>
#include <string>
#include <unordered_map>
#include <thread>
#include <random>

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
    // Request reqs = client.give_request("0", "5");
    Request reqs = client.give_request(args["start"].as<string>(), args["end"].as<string>());

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
    // Request reqs = client.give_request("0", "8");
    Request reqs = client.give_request(args["start"].as<string>(), args["end"].as<string>());
    
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
    // Request reqs = client.give_request("0", "1");
    Request reqs = client.give_request(args["start"].as<string>(), args["end"].as<string>());

    auto query_start = chrono::high_resolution_clock::now();
    auto pr_result = server.page_rank(reqs.F_1_s, reqs.P_s, reqs.constrained_key, reqs.ctr, args["epoch"].as<int>());
    auto query_end = chrono::high_resolution_clock::now();

    cout << chrono::duration<double>(query_end - query_start).count() << endl;

    size_t base = 1 << scaler;
    for (auto it = client.get_graph().vertices.begin(); it != client.get_graph().vertices.end(); it ++)
    {
        mpz_class weight;

        Vertex vr = {client.get_Dv2p().at(it->second.name), it->second.in_degree, it->second.out_degree};
        JL_decryption(client.get_sk(), client.get_pk(), pr_result.at(vr), weight);

        cout << "V: " << it->first << " Dec " << weight.get_str() 
             << " pr: " << float(weight.get_ui()) / float(1 << SCALE_SHIFT_P) << endl;
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


mpz_class la_inv(mpz_class input)
{
    mpz_class rtn(2);
    mpz_class base(1 << SCALE_SHIFT_P);
    mpz_class two(1 << (SCALE_SHIFT_P + 1));
    mpz_class tmp  = two - (rtn * input) / base;
    cout << "TMP: " << tmp.get_str() << endl;
    for (int i = 0; i < 4; i ++)
    {
        rtn = rtn * (two - (rtn * input / base)) / base;
        cout << " " << rtn.get_str() << endl;
    }
    return rtn;
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

            mpz_class la_res = la_inv(std::move(mpz_class(tmp)));

            mpz_class output;
            JL_decryption(sk, pk, out_enc, output);

            cout << output.get_str() << " " << la_res.get_str()  << endl;
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

void eval_ggm(cxxopts::ParseResult& args)
{
    // Prepare outdir
    fs::path outdir(args["outdir"].as<string>());
    outdir /= "ggm.json";
    if (!fs::exists(outdir))
    {
        fs::create_directories(outdir.parent_path());
    }

    ofstream os(outdir.string(), ofstream::out);

    // JSON stuff
    nlohmann::json j;


    // Init random source
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine generator(seed);
    uniform_int_distribution<int> distribution(0, 1 << MAX_GGM_DEPTH);
    auto dice = std::bind(distribution, generator);

    for (int i = 0; i < args["round"].as<int>(); i ++)
    {
        // Generate random number 
        int rn = dice();
        // A random key
        char key[KEY_SIZE] = {0};

        // Prepare GGM
        GGM ggm = {KEY_SIZE, MAX_GGM_DEPTH};
        Constrain con;
        Subkeys sks;
        auto start =  chrono::high_resolution_clock::now();
        ggm_find_best_range_cover(&ggm, key, 0, rn, &con);
        auto constrain = chrono::high_resolution_clock::now();
        ggm_derive(&ggm, &con, &sks);
        auto derive = chrono::high_resolution_clock::now();

        ggm_free_keys(&sks);
        ggm_free_constrain(&con);
        
        auto con_time = chrono::duration<float>(constrain - start).count() * 1000;
        auto drv_time = chrono::duration<float>(derive - constrain).count() / rn * 1000;

        cout << "Range: 0-" << rn << " Con time: " << con_time << " Derive time: " << drv_time << endl;
        j["exps"].push_back({{"Con", con_time}, {"Drv", drv_time}, {"Range", rn}});
    }

    float con_avg = 0.0;
    float drv_avg = 0.0;
    for (auto each : j["exps"])
    {
        con_avg += each["Con"].get<float>();
        drv_avg += each["Drv"].get<float>();
    }

    j["con_avg"] = con_avg / args["round"].as<int>();
    j["drv_avg"] = drv_avg / args["round"].as<int>();

    os << j.dump() << endl;
    os.close();
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
    {"page_rank", page_rank},
    {"eval_ggm", eval_ggm}
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
        ("round", "Round for experiments", cxxopts::value<int>()->default_value("10"))
        ("party", "Specify current party", cxxopts::value<string>())
        ("epoch", "Epoch for the page rank", cxxopts::value<int>()->default_value("50"))
        ("scale", "Scale up graph weight", cxxopts::value<bool>()->default_value("false"))
        ("start", "Start point", cxxopts::value<string>())
        ("end", "End point", cxxopts::value<string>())
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