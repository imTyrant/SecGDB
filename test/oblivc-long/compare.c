#include <stdio.h>
#include <stdlib.h>
#include <obliv.h>
#include "data_struct.h"

void compareaa(const char *host, const char *port, const int current_party)
{

    long long seed = 3569876435156948;
    srand(seed);

    long long r1 = rand();
    long long r2 = rand();

    INPUT input = {0};
    ProtocolDesc pd = {0};

    if (current_party == 1)
    {

        if (protocolConnectTcp2P(&pd, host, port))
        {
            printf("Connection failed\n");
        }
        setCurrentParty(&pd, current_party);

        for (int i = 0; i < 1; i++)
        {
            input.a_1 = rand() % 100 + r1;
            input.a_2 = rand() % 100 + r2;
            execYaoProtocol(&pd, compare, &input);
        }
    }
    if (current_party == 2)
    {
        if (protocolAcceptTcp2P(&pd, port))
        {
            printf("Listening failed\n");
        }

        for (int i = 0; i < 1; i++)
        {
            input.r_1 = r1;
            input.r_2 = r2;
            setCurrentParty(&pd, current_party);
            execYaoProtocol(&pd, compare, &input);
        }
    }
    cleanupProtocol(&pd);

    printf("I'm %d and the result is: %d\n", current_party, input.result);
}