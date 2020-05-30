#include <iostream>
#include <fstream>
#include <gmpxx.h>
#include <chrono>

#include "global.h"
#include "mpc.hpp"
#include "crypto_stuff.hpp"

extern "C"
{
#include <unistd.h>
#include "obliv.h"
#include "compare.h"
}


using namespace std;

void gen_random(mpz_class &r_left, mpz_class &r_right, int size)
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

    
    mpz_urandomb(r_left.get_mpz_t(), rand_st, size);
    mpz_urandomb(r_right.get_mpz_t(), rand_st, size);

    gmp_randclear(rand_st);
}


void secure_compare_remote(ProtocolDesc& pd, JL_PK& pk, JL_SK& sk, mpz_class& left, mpz_class& right)
{
    OBLIVC_IO io;
    mpz_class unblinded_left, unblinded_right;
    JL_decryption(sk, pk, left, unblinded_left);
    JL_decryption(sk, pk, right, unblinded_right);

    io.a_1 = unblinded_left.get_si();
    io.a_2 = unblinded_right.get_si();

    setCurrentParty(&pd, OBLIVC_PROXY);
    execYaoProtocol(&pd, compare, &io);
}

int secure_compare(ProtocolDesc& pd, PK& pk, mpz_class& left, mpz_class& right)
{
    g_compare_counter ++;
    int result = 0;
    auto start_time = std::chrono::high_resolution_clock::now();
#ifdef SEC_GDB_WITHOUT_ENCRYPTION
    if (left > right) { result  = COMPARE_HIGHER; }
    else if (left == right) { result = COMPARE_EQUAL; }
    else { result = COMPARE_LOWER; }
#else //SEC_GDB_WITHOUT_ENCRYPTION
    mpz_class r_left, r_right, r_left_enc, r_right_enc;
    
    // Subtract 2 is for preventing overflow
    gen_random(r_left, r_right, sizeof(OBLIVC_DATA_TYPE) * 8  - 2);

    JL_encryption(pk, r_left, r_left_enc);
    JL_encryption(pk, r_right, r_right_enc);
    
    mpz_class blinded_left = JL_homo_add(pk, left, r_left_enc);
    mpz_class blinded_right = JL_homo_add(pk, right, r_right_enc);

    OBLIVC_IO io;
    io.r_1 = r_left.get_si();
    io.r_2 = r_right.get_si();

    setCurrentParty(&pd, OBLIVC_SERVER);
    execYaoProtocol(&pd, compare, &io);
    result = io.result;
#endif //SEC_GDB_WITHOUT_ENCRYPTION
    auto end_time = std::chrono::high_resolution_clock::now();
    g_compare_time_cost += std::chrono::duration<double>(end_time - start_time).count();
    return result;
}

bool secure_compare_higher(ProtocolDesc& pd, PK& pk, mpz_class& left, mpz_class& right)
{   
    return secure_compare(pd, pk, left, right) == COMPARE_HIGHER;
}

bool secure_compare_lower(ProtocolDesc& pd, PK& pk, mpz_class& left, mpz_class& right)
{
    return secure_compare(pd, pk, left, right) == COMPARE_LOWER;
}

bool secure_compare_equal(ProtocolDesc& pd, PK& pk, mpz_class& left, mpz_class& right)
{
    return secure_compare(pd, pk, left, right) == COMPARE_EQUAL;
}


mpz_class secure_multiply(int socket, mpz_class& left, mpz_class& right)
{
    mpz_class rtn;
#ifdef SEC_GDB_WITHOUT_ENCRYPTION
    rtn = left * right;
#else

#endif
}