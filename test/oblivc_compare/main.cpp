#include <iostream>
#include <boost/algorithm/string.hpp>
#include <vector>

extern "C"
{
#include <obliv.h>
#include "data_struct.h"
}

using namespace std;

int main (int argc, char** argv)
{
    string remote_host;
    string port;
    FILE* fp = fopen("/dev/urandom", "r");
    long long seed;

    fread(&seed, sizeof(long long), 1, fp);
    srand(seed);
    fclose(fp);

    long long r1 = rand();
    long long r2 = rand();
    if (argc == 3)
    {
        vector<string> strs;
        boost::split(strs, argv[1], boost::is_any_of(":"));
        remote_host = strs[0];
        port = strs[1];

        INPUT input = {0};
        ProtocolDesc pd = {0};
        
        int current_party = std::stoi(argv[2]);

        if (current_party == 1)
        {
            
            if (0 != protocolConnectTcp2P(&pd, remote_host.c_str(), port.c_str()))
            {
                cout << "Connection failed\n";
                return EXIT_FAILURE;
            }
            setCurrentParty(&pd, current_party);

            for (int i = 0; i < 2; i ++)
            {
                long long a1 = rand() % 100;
                long long a2 = rand() % 100;
                cout << a1 << "\n";
                cout << a2 << "\n";
                input.a_1 = a1 + r1;
                input.a_2 = a2 + r2;
                execYaoProtocol(&pd, compare, &input);
            }
        }
        if (current_party == 2)
        {
            if (0 != protocolAcceptTcp2P(&pd, port.c_str()))
            {
                cout << "Listening failed\n";
                return EXIT_FAILURE;
            }
            
            for (int i = 0; i < 1; i++)
            {
                input.r_1 = r1;
                input.r_2 = r2;
                cout << input.r_1 << "\n";
                cout << input.r_2 << "\n";
                setCurrentParty(&pd, current_party);
                execYaoProtocol(&pd, compare, &input);
            }
        }
        cleanupProtocol(&pd);
        
        cout << "I'm " << current_party << " and the result is: " << input.result << "\n";
    }
}

//g++ main.o compare.o ../../obliv-c/_build/libobliv.a -lgcrypt -pthread