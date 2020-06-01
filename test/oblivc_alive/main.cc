#include <iostream>
#include <string>
#include <vector>
#include "cxxopts.hpp"

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <signal.h>
#include <execinfo.h>
#include <boost/stacktrace.hpp>
#include <boost/asio.hpp>


extern "C"
{
#include <obliv.h>
#include "data_struct.h"
}

using namespace std;
using namespace boost::stacktrace;
using namespace boost::asio;

void handler(int sig) {
  void *array[10];
  size_t size;

  // get void*'s for all entries on the stack
  size = backtrace(array, 10);

  // print out all the frames to stderr
  fprintf(stderr, "Error: signal %d:\n", sig);
  backtrace_symbols_fd(array, size, STDERR_FILENO);
  exit(1);
}

void server(const string& address, int port)
{
    INPUT input = {0};

    cout << "Server initializing...\n";
    ProtocolDesc pd = {0};
    // int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // if (sock < 0)
    // {
    //     cout << "Create socket failed\n";
    //     return;
    // }
    // cout << sock << endl;

    // int error = 0;
    // socklen_t el = sizeof(error);
    // setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &error, el);

    // struct sockaddr_in sa = {0};
    // sa.sin_family = AF_INET;
    // sa.sin_port = htons((short)port);
    // sa.sin_addr.s_addr = inet_addr(address.c_str());
    // if (bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0)
    // {
    //     cout << "Bind socket failed\n";
    //     return;
    // }

    // if (listen(sock, 20) < 0) {return;}
    
    // cout << "Listening at " << address << (long)port << endl;
    // struct sockaddr_in ca = {0};
    // socklen_t len_ca = sizeof(ca);
    // int csock = accept(sock, (struct sockaddr*)&ca, &len_ca);
    // if (csock < 0 ) 
    // {
    //     cout << "Establish connection with client failed\n";
    //     return;
    // }
    // cout << "Connected with client\n";

    io_service service;
    ip::tcp::acceptor acc(service, ip::tcp::endpoint(ip::tcp::v4(), (short)port));
    ip::tcp::socket socket(service);
    while(1)
    {
        acc.accept(socket);
        cout << "Client connected.." << endl;
        protocolUseTcp2PKeepAlive(&pd, socket.native_handle(), false);

        int counter = 0;
        while (1)
        {
            // int error = 0;
            // socklen_t len_e = sizeof(error);
            unsigned char a;
            int code = recv(socket.native_handle(), &a, sizeof(a), MSG_PEEK);
            cout << "Read code len " << code << endl;
            if (code < 1) {break;}
            input = {0};
            input.a_1 = 19 + counter;
            input.a_2 = 30;
            cout << "a1 " << input.a_1 - 10 << " a2 " << input.a_2 - 20 << endl;

            setCurrentParty(&pd, OBLIVC_PROXY);
            execYaoProtocol(&pd, compare, &input);
            cout << "Round " << counter++ << " Result:" << input.result << endl;
            boost::asio::read(socket, boost::asio::buffer(&code, sizeof(code)));
        }
        cleanupProtocol(&pd);
        socket.close();
    }
    acc.close();    
    cout << "Quiting \n";

    cout << "Client Quit\n";
}

void client(const string& address, int port)
{
    ProtocolDesc pd = {0};
    INPUT input = {0};

    FILE *fp = fopen("/dev/urandom", "r");
    long long seed;
    fread(&seed, sizeof(long long), 1, fp);
    srand(seed);
    fclose(fp);

    // sockaddr_in sa;
    // sa.sin_family = AF_INET;
    // sa.sin_port = htons((short)port);
    // sa.sin_addr.s_addr = inet_addr(address.c_str());

    // int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // int result = connect(sock, (sockaddr*)&sa, sizeof(sa));
    // if (result < 0)
    // {
    //     cout << "Connect to server failed\n";
    // }
    io_service service;
    ip::tcp::socket socket(service);
    ip::tcp::endpoint ep(ip::address::from_string(address), (short)port);
    socket.connect(ep);
    int sock = socket.native_handle();

    protocolUseTcp2PKeepAlive(&pd, sock, true);

    int counter = 3;
    while(counter)
    {
        input = {0};
        long long r1 = 10;
        long long r2 = 20;

        cout << "r1 " << r1 << " r2 " << r2 << endl;
        input.r_1 = r1;
        input.r_2 = r2;
        
        cout << "Client round:" << counter-- << endl;
        setCurrentParty(&pd, OBLIVC_SERVER);
        cout << "exec" << endl;
        execYaoProtocol(&pd, compare, &input);
        cout << "Result:" << input.result << endl;
    }
    cleanupProtocol(&pd);
    socket.close();

    cout << "Client Quit\n";
}

int main(int argc, char* argv[])
{
    signal(SIGSEGV, handler);
    
    cxxopts::Options options("Long Live Obliv-c");
    options.add_options()
        ("m,model", "client or server", cxxopts::value<string>())
        ("a,address", "address", cxxopts::value<string>()->default_value("12.0.0.1"))
        ("p,port", "port", cxxopts::value<int>()->default_value("23333"))
        ;

    auto result = options.parse(argc, argv);
    
    if (result["model"].as<string>() == "server")
    {
        server(result["address"].as<string>(), result["port"].as<int>());
    }
    else if (result["model"].as<string>() == "client")
    {
        client(result["address"].as<string>(), result["port"].as<int>());
    }
    else
    {
        cout << options.help() << endl;
    }
    
    

    return EXIT_SUCCESS;
}

// g++ ./main.cc compare.o -I ../../include/ -I ../../depends/cxxopts/include/ -I ../../depends/obliv-c/src/ext/oblivc/ ../../depends/obliv-c/_build/libobliv.a  -lboost_system -pthread -lgcrypt