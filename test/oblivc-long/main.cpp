#include <iostream>
#include <string>
#include <thread>
#include <mutex>

extern "C"
{
#include <obliv.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "compare.h"
#include "data_struct.h"
#include <sys/types.h>
#include <arpa/inet.h>
}

using namespace std;

mutex mtx;

string port("8080");
string remote_address("127.0.0.1");
bool quit;
bool ok;

long long ll;
long long rr;

void remote()
{
    int listenfd, sfd;
    sockaddr_in address;
    ProtocolDesc pd;

    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        cout << "P1\n";
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    if (bind(listenfd, (sockaddr *)&address, sizeof(address)) == -1)
    {
        cout << "P2\n";
        exit(EXIT_FAILURE);
    }
    if (listen(listenfd, 2) == -1)
    {
        cout << "P3\n";
        exit(EXIT_FAILURE);
    }

    if (sfd = accept(listenfd, (struct sockaddr *)NULL, NULL))
    {
        cout << "P4\n";
        exit(EXIT_FAILURE);
    }
    close(listenfd);
    protocolUseTcp2PKeepAlive(&pd, sfd, false);

    while(!quit)
    {
        INPUT input;
        input.a_1 = 10;
        input.a_2 = 20;
        setCurrentParty(&pd, OBLIVC_PROXY);
        execYaoProtocol(&pd, compare, &input);
    }
    cleanupProtocol(&pd);
}

int main(int argc, char** argv)
{
    int cfd;
    sockaddr_in sa;

    thread trd(remote);
    usleep(1000000);

    if ((cfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        cout << "S1\n";
        return EXIT_FAILURE;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(8080);
    inet_pton(AF_INET, remote_address.c_str(), &sa.sin_addr);

    if (connect(cfd, (sockaddr*)&sa, sizeof(sa)))
    {
        cout << "S2\n";
        return EXIT_FAILURE;
    }

    ProtocolDesc pd;
    protocolUseTcp2PKeepAlive(&pd, cfd, true);

    
    for (int i = 0; i < 1; i++)
    {
        INPUT input;
        srand(time(NULL));

        ll = rand() % 100 + 9;
        rr = rand() % 100 + 12;

        input.r_1 = 9;
        input.r_2 = 12;

        setCurrentParty(&pd, OBLIVC_SERVER);
        execYaoProtocol(&pd, compare, &input);

        cout << input.result << endl;
    }
    cleanupProtocol(&pd);

    trd.join();
}