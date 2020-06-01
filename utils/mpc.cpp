#include <iostream>
#include <fstream>
#include <gmpxx.h>
#include <chrono>
#include <boost/asio.hpp>

#include "global.h"
#include "mpc.hpp"
#include "crypto_stuff.hpp"
#include "network.hpp"
#include "exceptions.hpp"

extern "C"
{
#include <unistd.h>
#include "obliv.h"
#include "compare.h"
}


using namespace std;
using namespace boost::asio;
using boost::asio::ip::tcp;

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

void secure_compare_remote(ProtocolDesc& pd, JL_PK& pk, JL_SK& sk, tcp::socket& sock)
{
    mpz_class left, right, unblinded_left, unblinded_right;
    net_recv_mpz_class(sock, left);
    cout << "Receive one\n";
    net_recv_mpz_class(sock, right);
    cout << "Receive two\n";

    JL_decryption(sk, pk, left, unblinded_left);
    JL_decryption(sk, pk, right, unblinded_right);

    OBLIVC_IO io = {0};
    io.a_1 = unblinded_left.get_si();
    io.a_2 = unblinded_right.get_si();

    setCurrentParty(&pd, SEC_GDB_OBLIVC_PROXY);
    execYaoProtocol(&pd, compare, &io);
}

int secure_compare(ProtocolDesc& pd, JL_PK& jl_pk, mpz_class& left, mpz_class& right, tcp::socket& sock)
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
    
    // Subtracting 2 is for preventing overflow
    gen_random(r_left, r_right, sizeof(OBLIVC_DATA_TYPE) * 8  - 2);

    JL_encryption(jl_pk, r_left, r_left_enc);
    JL_encryption(jl_pk, r_right, r_right_enc);
    
    mpz_class blinded_left = JL_homo_add(jl_pk, left, r_left_enc);
    mpz_class blinded_right = JL_homo_add(jl_pk, right, r_right_enc);

    // Send data through socket
    net_send_mpz_class(sock, blinded_left);
    net_send_mpz_class(sock, blinded_right);

    OBLIVC_IO io = {0};
    io.r_1 = r_left.get_si();
    io.r_2 = r_right.get_si();

    setCurrentParty(&pd, SEC_GDB_OBLIVC_SERVER);
    execYaoProtocol(&pd, compare, &io);
    result = io.result;
#endif //SEC_GDB_WITHOUT_ENCRYPTION
    auto end_time = std::chrono::high_resolution_clock::now();
    g_compare_time_cost += std::chrono::duration<double>(end_time - start_time).count();
    return result;
}


void secure_multiply_remote(JL_PK& jl_pk, JL_SK& jl_sk, tcp::socket& sock)
{
    mpz_class blinded_left, blinded_right, left, right;
    net_recv_mpz_class(sock, blinded_left);
    net_recv_mpz_class(sock, blinded_right);

    JL_decryption(jl_sk, jl_pk, blinded_left, left);
    JL_decryption(jl_sk, jl_pk, blinded_right, right);

    mpz_class mul_tmp = left * right;
    mpz_class mul_tmp_enc;
    JL_encryption(jl_pk, mul_tmp, mul_tmp_enc);
    net_send_mpz_class(sock, mul_tmp_enc);
}

mpz_class secure_multiply(JL_PK& jl_pk, mpz_class& left, mpz_class& right, tcp::socket& sock)
{
    g_mul_counter ++;
    mpz_class rtn;
    auto start = std::chrono::high_resolution_clock::now();
#ifdef SEC_GDB_WITHOUT_ENCRYPTION
    rtn = left * right; // / 2p;
#else
    mpz_class r_left, r_right, r_left_enc, r_right_enc;
    gen_random(r_left, r_right, sizeof(OBLIVC_DATA_TYPE) / 2 - 1); // in case of overflow
    JL_encryption(jl_pk, r_left, r_left_enc);
    JL_encryption(jl_pk, r_right, r_right_enc);

    mpz_class blinded_left = JL_homo_add(jl_pk, left, r_left_enc);
    mpz_class blinded_right = JL_homo_add(jl_pk, right, r_right_enc);

    if (! net_send_mpz_class(sock, blinded_left))
    {
        cout << "Secure multiply sending left value error." << endl;
        return rtn;
    }
    if (! net_send_mpz_class(sock, blinded_right))
    {
        cout << "Secure multiply sending right value error." << endl;
        return rtn;
    }

    mpz_class mul_tmp_result;
    net_recv_mpz_class(sock, mul_tmp_result);

    mul_tmp_result = JL_homo_sub(jl_pk, mul_tmp_result, JL_homo_mul(jl_pk, left, r_right_enc));
    mul_tmp_result = JL_homo_sub(jl_pk, mul_tmp_result, JL_homo_mul(jl_pk, right, r_left_enc));
    mul_tmp_result = JL_homo_sub(jl_pk, mul_tmp_result, JL_homo_mul(jl_pk, r_left_enc, r_right_enc));

    mpz_class r3, r3_enc, abd;
    gen_random(r3, abd, sizeof(OBLIVC_DATA_TYPE)/2-1);
    JL_encryption(jl_pk, r3, r3_enc);
    mpz_class blinded_mul_tmp = JL_homo_add(jl_pk, mul_tmp_result, r3_enc);
    net_send_mpz_class(sock, blinded_mul_tmp);

    mpz_class result;
    net_recv_mpz_class(sock, result);
    rtn = JL_homo_sub(jl_pk, result, r3_enc);
#endif
    auto end = std::chrono::high_resolution_clock::now();
    g_mul_time_cost += std::chrono::duration<double>(end - start).count();
    return rtn;
}