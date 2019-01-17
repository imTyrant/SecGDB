#include <iostream>
#include <fstream>
#include <gmpxx.h>
#include <thread>

extern "C"
{
#include <unistd.h>
#include "obliv.h"
#include "compare.h"
}

#include "sec_compare.hpp"
#include "global.h"
#include "crypto_stuff.hpp"

#include "client.hpp"

using namespace std;

string remote_host("localhost");
string port("1234");

void remote_simulator(mpz_class left, mpz_class right)
{
    OBLIVC_IO io;
    ProtocolDesc pd;

    mpz_class unblined_left;
    mpz_class unblined_right;

    JL_decryption(g_client.get_sk(), g_client.get_pk(), left, unblined_left);
    JL_decryption(g_client.get_sk(), g_client.get_pk(), right, unblined_right);

    io.a_1 = unblined_left.get_si();
    io.a_2 = unblined_right.get_si();

    // cout << "ubld_l: " << io.a_1;
    // cout << " \tubld_r: " << io.a_2;

    if (0 != protocolAcceptTcp2P(&pd, port.c_str()))
    {
        cout << "Obliv-c listening failed\n";
        abort();
    }

    setCurrentParty(&pd, OBLIVC_PROXY);
    execYaoProtocol(&pd, compare, &io);
    cleanupProtocol(&pd);
}

void gen_random(mpz_class &r_left, mpz_class &r_right)
{
    unsigned char rand_buff[KEY_SIZE] = {0};

    mpz_class seed;

    ifstream in_file("/dev/urandom");

    if (!in_file.fail())
    {
        in_file.getline((char *)rand_buff, KEY_SIZE);
        in_file.close();
    }
    else
    {
        cout << "Fail to open random source\n";
        for (int i = 0; i < KEY_SIZE; i++)
        {
            rand_buff[i] = '0' + (char)i;
        }
    }

    mpz_import(seed.get_mpz_t(), sizeof(rand_buff), 1, sizeof(rand_buff[0]), 0, 0, rand_buff);
    gmp_randstate_t rand_st;
    gmp_randinit_default(rand_st);
    gmp_randseed(rand_st, seed.get_mpz_t());

    // Subtract 2 is for preventing overflow
    mpz_urandomb(r_left.get_mpz_t(), rand_st, sizeof(long long) * 8  - 2);
    mpz_urandomb(r_right.get_mpz_t(), rand_st, sizeof(long long) * 8  - 2);

    gmp_randclear(rand_st);    
}


// Wrapping garble circuit as a secure number compare funciton.
// The input are two encrypted number that are used to compare,
// and the result is a int
// 1 : left is greater than right
// 0 : left is equal to right
// -1 : the left is less than the right.
int secure_compare(PK& pk, mpz_class &left, mpz_class &right)
{
#ifdef SEC_GDB_WITHOUT_ENCRYPTION
    if (left > right) { return 1; }
    else if (left == right) {return 0; }
    else { return -1; }
#else
    mpz_class r_left;
    mpz_class r_right;
    mpz_class r_left_enc;
    mpz_class r_right_enc;

    gen_random(r_left, r_right);

    JL_encryption(pk, r_left, r_left_enc);
    JL_encryption(pk, r_right, r_right_enc);
    
    mpz_class blinded_left = JL_homo_add(pk, left, r_left_enc);
    mpz_class blinded_right = JL_homo_add(pk, right, r_right_enc);

    OBLIVC_IO io;

    io.r_1 = r_left.get_si();
    io.r_2 = r_right.get_si();

    // cout << "io l: " << left.get_ui();
    // cout << " \tio r: " << right.get_ui() << endl;

    // cout << "io lr: " << io.r_1;
    // cout << " \tio rr: " << io.r_2 << endl;

    // mpz_class tmpl = left + r_left;
    // mpz_class tmpr = right + r_right;

    // cout << "l + rl:" << tmpl.get_str();
    // cout << " \tr + rr:" << tmpr.get_str() << endl;

    // cout << "bldl:" << blinded_left.get_str();
    // cout << " \tbldr:" << blinded_right.get_str() << endl;

    ProtocolDesc pd;

    thread remote(remote_simulator, blinded_left, blinded_right);

    // usleep(TIME_INTERVAL); // Sleep some time for preventing misorder of threads.
    int retry_time = RETRY_TIME;

    while (0 != protocolConnectTcp2P(&pd, remote_host.c_str(), port.c_str()) && retry_time > 0)
    {
        if (--retry_time == 0) 
        {
            cout << "Obliv-c connection failed, retry time left: " << retry_time << "\n";
            abort();
        }
        usleep(TIME_INTERVAL);
        // abort();
    }

    setCurrentParty(&pd, OBLIVC_SERVER);
    execYaoProtocol(&pd, compare, &io);
    cleanupProtocol(&pd);

    remote.join();
    g_compare_counter ++;
    return io.result;
#endif
}

bool secure_compare_greater(PK& pk, mpz_class &left, mpz_class &right)
{
    return secure_compare(pk, left, right) == 1;
}

bool secure_compare_less(PK& pk, mpz_class &left, mpz_class &right)
{
    return secure_compare(pk, left, right) == -1;
}

bool secure_compare_equal(PK& pk, mpz_class &left, mpz_class &right)
{
    return secure_compare(pk, left, right) == 0;
}