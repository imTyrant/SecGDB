#ifndef SEC_GDB_H_MPC
#define SEC_GDB_H_MPC


#define COMPARE_HIGHER 1
#define COMPARE_LOWER -1
#define COMPARE_EQUAL 0

#include <gmpxx.h>
#include "crypto_stuff.hpp"

void secure_compare_remote(ProtocolDesc& pd, JL_PK& pk, JL_SK& sk, mpz_class& left, mpz_class& right);

int secure_compare(ProtocolDesc& pd, PK& pk, mpz_class& left, mpz_class& right);

bool secure_compare_higher(ProtocolDesc& pd, PK& pk, mpz_class& left, mpz_class& right);

bool secure_compare_lower(ProtocolDesc& pd, PK& pk, mpz_class& left, mpz_class& right);

bool secure_compare_equal(ProtocolDesc& pd, PK& pk, mpz_class& left, mpz_class& right);


extern size_t g_compare_counter;
extern double g_compare_time_cost;

#endif // SEC_GDB_H_MPC