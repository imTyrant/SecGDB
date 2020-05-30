#include <iostream>
#include "depends/cxxopts/include/cxxopts.hpp"
#include <boost/asio.hpp>
#include <string>
#include <thread>

using namespace std;
using namespace boost::asio;

void server(const string& address, short port)
{
    cout << "I'm server.." << endl;
    io_service service;
    ip::tcp::acceptor acc(service, ip::tcp::endpoint(ip::tcp::v4(), port));
    for(;;)
    {
        ip::tcp::socket clt(service);
        acc.accept(clt);
        while(true)
        {
            char head[1];
            boost::system::error_code ec;
            clt.read_some(boost::asio::buffer(head), ec);
            if (head[0] == 'q' || ec == boost::asio::error::eof)
            {
                cout << "Quiting.." << endl;
                break;
            }
            else if (ec)
            {
                cout << "Error occurs" << endl;
            }
            cout << head[0] << endl;
        }
        clt.close();
    }
}

void client(const string& address, short port)
{
    cout << "I'm client.." << endl;
    io_service service;
    ip::tcp::socket sock(service);
    ip::tcp::endpoint ep(ip::address::from_string(address), port);
    sock.connect(ep);
    while (true)
    {
        char buff[1];
        cin >> buff;
        if (buff[0] == 'q')
        {
            sock.close();
            break;
        }
        sock.write_some(boost::asio::buffer(buff));
    }
    cout << "Quiting.." << endl;
}

int main(int argc, char** argv)
{
    cxxopts::Options options("");

    options.add_options()
        ("party", "", cxxopts::value<string>())
        ("a,address", "", cxxopts::value<string>()->default_value("127.0.0.1"))
        ("p,port", "", cxxopts::value<short>()->default_value("23333"))
        ;

    auto args = options.parse(argc, argv);

    if (args["party"].as<string>() == "server")
    {
        server(args["address"].as<string>(), args["port"].as<short>());
    }
    else
    {
        client(args["address"].as<string>(), args["port"].as<short>());
    }
    
    return EXIT_SUCCESS;
}