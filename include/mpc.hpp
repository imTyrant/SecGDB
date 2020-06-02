#ifndef SEC_GDB_H_MPC
#define SEC_GDB_H_MPC


#define COMPARE_HIGHER 1
#define COMPARE_LOWER -1
#define COMPARE_EQUAL 0

#include <gmpxx.h>
#include <boost/asio.hpp>

#include "crypto_stuff.hpp"

extern "C"
{
#include "obliv.h"
}

void secure_compare_remote(ProtocolDesc& pd, JL_PK& pk, JL_SK& sk, boost::asio::ip::tcp::socket& sock);
int secure_compare(ProtocolDesc& pd, JL_PK& pk, mpz_class& left, mpz_class& right, boost::asio::ip::tcp::socket& sock);

void secure_multiply_remote(JL_PK& jl_pk, JL_SK& jl_sk, boost::asio::ip::tcp::socket& sock);
mpz_class secure_multiply(JL_PK& jl_pk, mpz_class& left, mpz_class& right, boost::asio::ip::tcp::socket& sock, int scaler=0);

void secure_inverse_remote(JL_PK& jl_pk, JL_SK& jl_sk, boost::asio::ip::tcp::socket& sock);
mpz_class secure_inverse(JL_PK& jl_pk, mpz_class& input, boost::asio::ip::tcp::socket& sock, int scaler=0);

void test_obc(ProtocolDesc& pd);

extern size_t g_compare_counter;
extern double g_compare_time_cost;

extern size_t g_mul_counter;
extern double g_mul_time_cost;

extern size_t g_ivs_counter;
extern double g_ivs_time_cost;

#endif // SEC_GDB_H_MPC