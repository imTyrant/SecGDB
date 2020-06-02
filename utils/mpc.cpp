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
#include "mpc_compare.h"
}

#ifdef SEC_GDB_DBG
#include "client.hpp"
#endif

using namespace std;
using namespace boost::asio;
using boost::asio::ip::tcp;

void gen_random_single(mpz_class& in, int size)
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
        cerr << "Fail to open random source\n";
        for (int i = 0; i < KEY_SIZE; i++)
        {
            rand_buff[i] = '0' + (char)i;
        }
    }

    mpz_import(seed.get_mpz_t(), sizeof(rand_buff), 1, sizeof(rand_buff[0]), 0, 0, rand_buff);
    gmp_randstate_t rand_st;
    gmp_randinit_default(rand_st);
    gmp_randseed(rand_st, seed.get_mpz_t());

    mpz_urandomb(in.get_mpz_t(), rand_st, size);

    gmp_randclear(rand_st);
}

void gen_random(mpz_class &r_left, mpz_class &r_right, int size)
{
    gen_random_single(r_left, size);
    gen_random_single(r_right, size);
}

void secure_compare_remote(ProtocolDesc& pd, JL_PK& pk, JL_SK& sk, tcp::socket& sock)
{
    mpz_class left, right, unblinded_left, unblinded_right;
    net_recv_mpz_class(sock, left);
    log_dbg("Receive one\n");
    net_recv_mpz_class(sock, right);
    log_dbg("Receive two\n");

    JL_decryption(sk, pk, left, unblinded_left);
    JL_decryption(sk, pk, right, unblinded_right);

    OBLIVC_IO io = {0};
    io.a_1 = unblinded_left.get_si();
    io.a_2 = unblinded_right.get_si();
    log_dbg_fmt("a1 %s a2 %s\n", unblinded_left.get_str().c_str(),  unblinded_right.get_str().c_str());

    ProtocolDesc ppd = {0};
    protocolUseTcp2PKeepAlive(&ppd, sock.native_handle(), false);
    setCurrentParty(&ppd, SEC_GDB_OBLIVC_PROXY);
    execYaoProtocol(&ppd, compare, &io);
    cleanupProtocol(&ppd);
    log_dbg_fmt("Result %d\n", io.result);
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

#ifdef SEC_GDB_DBG
    mpz_class l, r;
    JL_decryption(g_sk.jl_sk, g_pk.jl_pk, left, l);
    JL_decryption(g_sk.jl_sk, g_pk.jl_pk, right, r);
    log_dbg_fmt("Original r: %s l: %s\n", l.get_str().c_str(), r.get_str().c_str());
#endif

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
    log_dbg_fmt("r1: %s r2: \n", r_left.get_str().c_str(), r_right.get_str().c_str());

    ProtocolDesc ppd = {0};
    protocolUseTcp2PKeepAlive(&ppd, sock.native_handle(), true);
    setCurrentParty(&ppd, SEC_GDB_OBLIVC_SERVER);
    execYaoProtocol(&ppd, compare, &io);
    cleanupProtocol(&ppd);

    result = io.result;
    log_dbg_fmt("Result %d\n", io.result);
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
    log_dbg_fmt("left %s right %s\n", left.get_str().c_str(), right.get_str().c_str());

    mpz_class mul_tmp = left * right;
    mpz_class mul_tmp_enc;
    JL_encryption(jl_pk, mul_tmp, mul_tmp_enc);
    net_send_mpz_class(sock, mul_tmp_enc);

    /* Scale down phase */
    mpz_class fin, fin_enc, base, result;
    net_recv_mpz_class(sock, base);
    net_recv_mpz_class(sock, fin_enc);

    JL_decryption(jl_sk, jl_pk, fin_enc, fin);

    log_dbg_fmt("fin %s\n", fin.get_str().c_str());
    fin = fin / base;
    log_dbg_fmt("fin / base %s\n", fin.get_str().c_str());

    JL_encryption(jl_pk, fin, result);
    net_send_mpz_class(sock, result);
    log_dbg("Multiply remote finished.");
}

mpz_class secure_multiply(JL_PK& jl_pk, mpz_class& left, mpz_class& right, tcp::socket& sock, int scaler)
{
    g_mul_counter ++;
    mpz_class rtn;
    auto start = std::chrono::high_resolution_clock::now();
    mpz_class base(1);
    base <<= scaler;
#ifdef SEC_GDB_WITHOUT_ENCRYPTION
    rtn = left * right / base;
#else
    mpz_class r_left, r_right, r_left_enc, r_right_enc, r_mul;

// #ifdef SEC_GDB_DBG
//     mpz_class l, r;
//     JL_decryption(g_sk.jl_sk, g_pk.jl_pk, left, l);
//     JL_decryption(g_sk.jl_sk, g_pk.jl_pk, right, r);
//     log_dbg_fmt("Original r: %s l: %s\n", l.get_str().c_str(), r.get_str().c_str());
// #endif
    
    gen_random(r_left, r_right, sizeof(OBLIVC_DATA_TYPE) * 4 - 1); // in case of overflow
    log_dbg_fmt("r1 %s r2 %s\n", r_left.get_str().c_str(), r_right.get_str().c_str());
    
    JL_encryption(jl_pk, r_left, r_left_enc);
    JL_encryption(jl_pk, r_right, r_right_enc);
    mpz_class r_mul_tmp = r_left * r_right;
    JL_encryption(jl_pk, r_mul_tmp, r_mul);

    mpz_class blinded_left = JL_homo_add(jl_pk, left, r_left_enc);
    mpz_class blinded_right = JL_homo_add(jl_pk, right, r_right_enc);

    net_send_mpz_class(sock, blinded_left);
    net_send_mpz_class(sock, blinded_right);

    mpz_class mul_tmp_result;
    net_recv_mpz_class(sock, mul_tmp_result);

    mul_tmp_result = JL_homo_sub(jl_pk, mul_tmp_result, JL_homo_mul(jl_pk, left, r_right));
    mul_tmp_result = JL_homo_sub(jl_pk, mul_tmp_result, JL_homo_mul(jl_pk, right, r_left));
    mul_tmp_result = JL_homo_sub(jl_pk, mul_tmp_result, r_mul);

    /* Scale down */
    mpz_class r3, r3_enc, r3_div, r3_div_enc;
    gen_random_single(r3, sizeof(OBLIVC_DATA_TYPE) * 4 - 1);
    log_dbg_fmt("r3 %s\n", r3.get_str().c_str());
    r3_div = r3 / base;
    log_dbg_fmt("half r3 %s\n", r3_div.get_str().c_str());

    JL_encryption(jl_pk, r3, r3_enc);
    JL_encryption(jl_pk, r3_div, r3_div_enc);

    mul_tmp_result = JL_homo_add(jl_pk, mul_tmp_result, r3_enc);
    net_send_mpz_class(sock, base);
    net_send_mpz_class(sock, mul_tmp_result);

    net_recv_mpz_class(sock, rtn);
    rtn = JL_homo_sub(jl_pk, rtn, r3_div_enc);

#endif
    auto end = std::chrono::high_resolution_clock::now();
    g_mul_time_cost += std::chrono::duration<double>(end - start).count();
    return rtn;
}


void secure_inverse_remote(JL_PK& jl_pk, JL_SK& jl_sk, tcp::socket& sock)
{
    for (int i = 0; i < INVERSE_ITERS; i ++)
    {
        secure_multiply_remote(jl_pk, jl_sk, sock);
        secure_multiply_remote(jl_pk, jl_sk, sock);
    }
}

mpz_class secure_inverse(JL_PK& jl_pk, mpz_class& input, tcp::socket& sock, int scaler)
{
    g_ivs_counter++;
    auto start = std::chrono::high_resolution_clock::now();
    mpz_class rtn(2); // Find a very very small value to the root (rtn / base)
    mpz_class base(1);
    base <<= scaler;
    mpz_class two(2);
    two = two * base; // scale up 2
#ifdef SEC_GDB_WITHOUT_ENCRYPTION
    /* Potential bug alert */
    for (int i = 0; i < INVERSE_ITERS; i ++)
    {
        rtn = rtn * (two  - (input * rtn) / base) / base;
    }
#else
    mpz_class two_enc, rtn_enc;
    JL_encryption(jl_pk, two, two_enc);
    JL_encryption(jl_pk, rtn, rtn_enc);
    for (int i = 0; i < INVERSE_ITERS; i ++)
    {
        mpz_class tmp1 = secure_multiply(jl_pk, input, rtn_enc, sock, scaler);
        mpz_class tmp2 = JL_homo_sub(jl_pk, two_enc, tmp1);
        rtn_enc = secure_multiply(jl_pk, rtn_enc, tmp2, sock, scaler);
    }
    rtn = rtn_enc;
#endif
    auto end = std::chrono::high_resolution_clock::now();
    g_ivs_time_cost += std::chrono::duration<double>(end - start).count();
    return rtn;
}