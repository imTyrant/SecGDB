// g++ crypto_stuff.cpp -g ../labhe/build/liblabhe.a -I ../labhe/include/ -I ../include/ -lgmpxx -lgmp -lcrypto -D SEC_GDB_DBG_CRYPTO

#include <iostream>
#include <fstream>
#include <gmpxx.h>
#include <vector>

#include "global.h"
#include "crypto_stuff.hpp"

extern "C"
{
#include "bhjl.h"
#include "bhjl_gen.h"
}

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <openssl/sha.h>

using namespace std;

/**
 * Hash function which is used in paper.
*/
void H_1(unsigned char *key, size_t key_size, unsigned char *in, size_t data_size, unsigned char *out)
{
    int rtn_size;

#ifdef SECURITY_LEVEL_128
    HMAC(EVP_sha1(), key, (int)key_size, in, data_size, out, (unsigned int *)&rtn_size);
#else
    HMAC(EVP_sha256(), key, (int)key_size, in, data_size, out, (unsigned int *)&rtn_size);
#endif
}

/**
 * Hash function which is used in paper.
 * Same function,
*/
void H_2(unsigned char *key, size_t key_size, unsigned char *in, size_t data_size, unsigned char *out)
{
    string str = string((char *)key);
    std::reverse(str.begin(), str.end());
#ifdef NOT_SAME_HASH
    //Nee a alternative hash algorithm.
    //Have no idea currently....
#else
    H_1((unsigned char*)str.c_str(), key_size, in, data_size, out);
#endif
}

/**
 * Use HAMC-SHA256 as a keyed hash function.
*/
size_t F(unsigned char *key, size_t key_size, unsigned char *in, size_t data_size, unsigned char *out)
{
    size_t rtn_size;

#ifdef SECURITY_LEVEL_128
    HMAC(EVP_sha1(), key, (int)key_size, in, data_size, out, (unsigned int *)&rtn_size);
#else
    HMAC(EVP_sha256(), key, (int)key_size, in, data_size, out, (unsigned int *)&rtn_size);
#endif

    return rtn_size;
}

/**
 * This function is used to generate the SK to be used.
*/
bool sample_key(SK &sk, PK &pk)
{
    unsigned char rand_buff[KEY_SIZE];
    mpz_class k1, k2, k3;

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

    if (0 != bhjl_gen(sk.jl_sk.p.get_mpz_t(), pk.jl_pk.N.get_mpz_t(), pk.jl_pk.y.get_mpz_t(),
                        pk.jl_pk.k.get_mpz_t(), JL_MODULUS, SECURITY_LEVEL, rand_st))
    {
        cout << "JL scheme initlization failed\n";
        return false;
    }

    char buff[SECURITY_LEVEL];

    mpz_urandomb(k1.get_mpz_t(), rand_st, SECURITY_LEVEL);
    mpz_get_str(buff, 16, k1.get_mpz_t());
    sk.k_1 = vector<unsigned char>(begin(buff), end(buff));
    memset(buff, 0, sizeof(buff));

    mpz_urandomb(k2.get_mpz_t(), rand_st, SECURITY_LEVEL);
    mpz_get_str(buff, 16, k2.get_mpz_t());
    sk.k_2 = vector<unsigned char>(begin(buff), end(buff));
    memset(buff, 0, sizeof(buff));

    mpz_urandomb(k3.get_mpz_t(), rand_st, SECURITY_LEVEL);
    mpz_get_str(buff, 16, k3.get_mpz_t());
    sk.k_3 = vector<unsigned char>(begin(buff), end(buff));

    gmp_randclear(rand_st);

    return true;
}

/**
 * You know, cleaning up is a good habit.
*/
void sk_clear(SK &sk)
{
    sk.k_1.clear();
    sk.k_2.clear();
    sk.k_3.clear();
}

void pk_clear(PK &pk)
{
}

/**
 * A wrapped JL scheme encryption alogrithm
 * Yeah... the last one is the return value.. History....
*/
void JL_encryption(SK &sk, PK &pk, size_t &num, mpz_class &out)
{
    mpz_set_ui(out.get_mpz_t(), num);
}


/**
 * 
*/
void masking(const void* input, size_t size, unsigned char* mask, size_t mask_size, unsigned char* out)
{
    size_t round = size / mask_size;
    size_t rest = size % mask_size;

    const unsigned char* tmp = (unsigned char*)input;

    size_t base = 0;
    for (size_t i = 0; i < round; i++)
    {
        
        for (size_t j = 0; j < mask_size; j++)
        {
            out[base + j] = tmp[base + j] ^ mask[j];
        }

        base = mask_size * (i + 1);
    }

    for (size_t i = 0; i < rest; i++)
    {
        out[base + i] = tmp[base + i] ^ mask[i];
    }
}


#ifdef SEC_GDB_DBG_CRYPTO
int main(int argc, char **argv)
{
    SK sk;
    PK pk;

    sample_key(sk, pk);
    // fprintf(stdout, "\nsk.k_1: ");
    // // mpz_out_str(stdout, 10, sk.k_1);
    // cout << sk.k_1;
    // fprintf(stdout, "\nsk.k_2: ");
    // // mpz_out_str(stdout, 10, sk.k_2);
    // cout << sk.k_2;
    // fprintf(stdout, "\nsk.k_3: ");
    // // mpz_out_str(stdout, 10, sk.k_3);
    // cout << sk.k_3; cout << "\n" << sk.k_3.length();

    fprintf(stdout, "\nsk.jl_sk.p: ");
    cout << sk.jl_sk.p.get_str();
    // mpz_out_str(stdout, 10, sk.jl_sk.p);
    fprintf(stdout, "\npk.jl_pk.k: ");
    cout << pk.jl_pk.k.get_str();
    // mpz_out_str(stdout, 10, pk.jl_pk.k);
    fprintf(stdout, "\npk.jl_pk.N: ");
    cout << pk.jl_pk.N.get_str();
    // mpz_out_str(stdout, 10, pk.jl_pk.N);
    fprintf(stdout, "\npk.jl_pk.y: ");
    cout << pk.jl_pk.y.get_str();
    // mpz_out_str(stdout, 10, pk.jl_pk.y);

    cout << "\n";

    vector<unsigned char> test;

    unsigned char a[] = "this is a loooooooooooooooooooooooooooooooooooong string!!";

    test.assign(std::begin(a), std::end(a));

    string b = "this is mask!";
    unsigned char out[test.size()] = {0};

    masking(test.data(), test.size(), (unsigned char*)b.c_str(), b.length(), out);

    cout << out;

    vector<unsigned char> c(out, out + test.size());

    cout << c.size() << "   " << test.size();

    masking(out, test.size(), (unsigned char*)b.c_str(), b.length(), out);

    cout << out;
}
#endif