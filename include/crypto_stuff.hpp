#ifndef SEC_GDB_H_CRYPTO
#define SEC_GDB_H_CRYPTO

#include <iostream>
#include <gmpxx.h>

#ifdef SECURITY_LEVEL_128
#define JL_MODULUS 1024
#else
#define JL_MODULUS 2048
#endif

/******************** Types ********************/
typedef struct _JL_SK
{
    mpz_class p;
} JL_SK;

typedef struct _JL_PK
{
    mpz_class N;
    mpz_class y;
    mpz_class k;
} JL_PK;

// k_1, k_2, k_3 are stored in vector as I cannot find a good container 
// for raw char. But in the <client.cpp> I use std::string to store 
// raw char. Uhn... it is little confusing.
typedef struct _SK
{
    std::vector<unsigned char> k_1;
    std::vector<unsigned char> k_2;
    std::vector<unsigned char> k_3;
    JL_SK jl_sk;
} SK;

typedef struct _PK
{
    JL_PK jl_pk;
} PK;

/******************** Functions ********************/
void H_1(
    unsigned char *key,
    size_t key_size,
    unsigned char *in,
    size_t data_size,
    unsigned char *out);

void H_2(
    unsigned char *key,
    size_t key_size,
    unsigned char *in,
    size_t data_size,
    unsigned char *out);

size_t F(
    unsigned char *key,
    size_t key_size,
    unsigned char *in,
    size_t data_size,
    unsigned char *out);

bool sample_key(SK &sk, PK &pk);

void sk_clear(SK &sk);

void pk_clear(PK &pk);

void JL_encryption(SK &sk, PK &pk, size_t &num, mpz_class &out);

void masking(const void* input, size_t size, unsigned char* mask, size_t mask_size, unsigned char* out);

#endif
