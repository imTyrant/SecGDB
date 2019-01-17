#ifndef SEC_GDB_H_SEC_COMPARE
#define SEC_GDB_H_SEC_COMPARE

#include <gmpxx.h>
#include "crypto_stuff.hpp"

#define TIME_INTERVAL 5000
#define RETRY_TIME 10

int secure_compare(PK& pk, mpz_class &left, mpz_class &right);

extern size_t g_compare_counter;

#endif