#ifndef SEC_GDB_H_SEC_COMPARE
#define SEC_GDB_H_SEC_COMPARE

#include <gmpxx.h>
#include "crypto_stuff.hpp"

#define TIME_INTERVAL 50000
#define RETRY_TIME 100

int secure_compare(PK& pk, mpz_class &left, mpz_class &right);

bool secure_compare_greater(PK& pk, mpz_class &left, mpz_class &right);

bool secure_compare_less(PK& pk, mpz_class &left, mpz_class &right);

bool secure_compare_equal(PK& pk, mpz_class &left, mpz_class &right);

// Use this parameter to calculate total time wasted.
extern size_t g_compare_counter;

#endif