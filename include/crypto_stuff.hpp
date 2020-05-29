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
    mpz_class pm12k;
} JL_SK;

typedef struct _JL_PK
{
    mpz_class N;
    mpz_class y;
    mpz_class k;
    mpz_class _2k1;
    mpz_class _2k;
} JL_PK;

typedef struct _SK
{
    std::string k_1;
    std::string k_2;
    std::string k_3;
    JL_SK jl_sk;
} SK;

typedef struct _PK
{
    JL_PK jl_pk;
} PK;

/******************** Functions ********************/
size_t get_mpz_raw(void* buff, mpz_ptr src);

std::string let_mpz_raw_to_str(mpz_ptr src);

void set_mpz_raw(mpz_ptr dest, size_t size, const void* buff);

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

void JL_encryption(PK &pk, size_t num, mpz_class &out);

void JL_encryption(PK &pk, mpz_class &in, mpz_class &out);

void JL_decryption(SK &sk, PK &pk, mpz_class &in, size_t* out);

void JL_decryption(SK &sk, PK &pk, mpz_class &in, mpz_class &out);

mpz_class JL_homo_add(PK &pk, mpz_class &left, mpz_class &right);

mpz_class JL_homo_sub(PK &pk, mpz_class &left, mpz_class &right);

mpz_class JL_homo_mul(PK &pk, mpz_class &left, mpz_class &right);

void masking(const void* input, size_t size, unsigned char* mask, size_t mask_size, unsigned char* out);

#endif
