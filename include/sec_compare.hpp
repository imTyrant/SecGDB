#ifndef SEC_GDB_H_SEC_COMPARE
#define SEC_GDB_H_SEC_COMPARE

#include <gmpxx.h>
#include "crypto_stuff.hpp"

#define TIME_INTERVAL 5000
#define RETRY_TIME 100

#define SC_GREATER 1 // left > right
#define SC_LESS -1 // left < right
#define SC_EQUAL 0 // left == right

int secure_compare(PK& pk, mpz_class &left, mpz_class &right);

bool secure_compare_greater(PK& pk, mpz_class &left, mpz_class &right);

bool secure_compare_less(PK& pk, mpz_class &left, mpz_class &right);

bool secure_compare_equal(PK& pk, mpz_class &left, mpz_class &right);

// Use this parameter to calculate total time wasted.
extern size_t g_compare_counter;

extern double g_total_wait_time;

extern double g_total_compare_time;
#endif