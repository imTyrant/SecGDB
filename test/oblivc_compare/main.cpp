#include <iostream>
#include <boost/algorithm/string.hpp>
#include <vector>
#include <thread>

extern "C"
{
#include <obliv.h>
#include "data_struct.h"
}

using namespace std;

string remote_host("localhost");
string port("1234");

void secure_compare(long long a1, long long a2)
{
    INPUT input = {0};
    ProtocolDesc pd = {0};
    input.a_1 = a1;
    input.a_2 = a2;
    
    if (0 != protocolAcceptTcp2P(&pd, port.c_str()))
    {
        cout << "Listening failed\n";
        return;
    }

    setCurrentParty(&pd, OBLIVC_PROXY);
    execYaoProtocol(&pd, compare, &input);
    cleanupProtocol(&pd);
}

int main(int argc, char **argv)
{
    for (int i = 0; i < 100; i++)
    {
        FILE *fp = fopen("/dev/urandom", "r");
        long long seed;

        fread(&seed, sizeof(long long), 1, fp);
        srand(seed);
        fclose(fp);

        ProtocolDesc pd = {0};

        long long r1 = rand();
        long long r2 = rand();

        // cout << r1 << " R1 \n";
        // cout << r2 << " R1 \n";

        INPUT input = {0};

        long long a1 = rand() % 100;
        long long a2 = rand() % 100;

        // cout << a1 << "  A1 \n";
        // cout << a2 << "  A2 \n";

        int supposed_result = 0;
        if (a1 > a2)
        {
            supposed_result = 1;
            // cout << "supposed output is 1\n";
        }
        else if (a1 == a2)
        {
            supposed_result = 0;
            // cout << "supposed output is 2\n";
        }
        else
        {
            supposed_result = -1;
            // cout << "supposed output is 3\n";
        }

        input.r_1 = r1;
        input.r_2 = r2;

        thread remote(secure_compare, a1 + r1, a2 + r2);
        usleep(100000);

        if (0 != protocolConnectTcp2P(&pd, remote_host.c_str(), port.c_str()))
        {
            cout << "Connection failed\n";
            return EXIT_FAILURE;
        }
        setCurrentParty(&pd, OBLIVC_SERVER);
        execYaoProtocol(&pd, compare, &input);
        cleanupProtocol(&pd);

        remote.join();

        if (supposed_result == input.result)
        {
            cout << "ok...\n";
        }
        else
        {
            cout << "emmmm...\n";
        }
        // cout << "I'm "
        //      << "1"
        //      << " and the result is: " << input.result << "\n";
    }
}

//g++ main.o compare.o ../../obliv-c/_build/libobliv.a -lgcrypt -pthread