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
 * Wrap the export function of GMP mpz_t
 * Take a big enough buffer and mpz_class
 * Output the total byte got.
*/
size_t get_mpz_raw(void* buff, mpz_ptr src)
{
    size_t byte_get = 0;
    mpz_export(buff, &byte_get, WRAPPING_GMP_EXPORT_FORMAT_ORDER, WRAPPING_GMP_EXPORT_FORMAT_SIZE,
                WRAPPING_GMP_EXPORT_FORMAT_ENDIAN, WRAPPING_GMP_EXPORT_FORMAT_NAIL, src);
    return byte_get;
}
/**
 * Wrap the export function of GMP mpz_t
 * Take a big enough buffer and mpz_class
 * Output the total byte got.
*/
string let_mpz_raw_to_str(mpz_ptr src)
{
    
    size_t byte_get = 0;
    char* bytes = (char*)mpz_export(NULL, &byte_get, WRAPPING_GMP_EXPORT_FORMAT_ORDER, WRAPPING_GMP_EXPORT_FORMAT_SIZE,
                WRAPPING_GMP_EXPORT_FORMAT_ENDIAN, WRAPPING_GMP_EXPORT_FORMAT_NAIL, src);
    string rtn = string(bytes, byte_get);
    free(bytes);
    return rtn;
}
/**
 * Wrap the export function of GMP mpz_t
 * Take a big enough buffer and mpz_class
 * Output the total byte got.
*/
void set_mpz_raw(mpz_ptr dest, size_t size, const void* buff)
{
    mpz_import(dest, size, WRAPPING_GMP_EXPORT_FORMAT_ORDER, WRAPPING_GMP_EXPORT_FORMAT_SIZE,
                WRAPPING_GMP_EXPORT_FORMAT_ENDIAN, WRAPPING_GMP_EXPORT_FORMAT_NAIL, buff);
}

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
    string str = string((char *)key, key_size);
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
    size_t rtn_size = 0;
#ifdef F_FUNCTION_DISABLE
    unsigned char tmp[KEY_SIZE] = {0};
    memcpy(tmp, in, (data_size > KEY_SIZE) ? KEY_SIZE : data_size);
    memcpy(out, tmp, KEY_SIZE);
    return KEY_SIZE;
#else
#ifdef SECURITY_LEVEL_128
    HMAC(EVP_sha1(), key, (int)key_size, in, data_size, out, (unsigned int *)&rtn_size);
#else
    HMAC(EVP_sha256(), key, (int)key_size, in, data_size, out, (unsigned int *)&rtn_size);
#endif
#endif

    return rtn_size;
}

/**
 * This function is used to generate the SK to be used.
*/
bool sample_key(SK &sk, PK &pk)
{
    unsigned char rand_buff[KEY_SIZE] = {0};
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

    bhjl_precom(pk.jl_pk._2k1.get_mpz_t(), pk.jl_pk._2k.get_mpz_t(), 
            sk.jl_sk.pm12k.get_mpz_t(), sk.jl_sk.p.get_mpz_t(), SECURITY_LEVEL);

    mpz_urandomb(k1.get_mpz_t(), rand_st, SECURITY_LEVEL);
    sk.k_1 = let_mpz_raw_to_str(k1.get_mpz_t());

    mpz_urandomb(k2.get_mpz_t(), rand_st, SECURITY_LEVEL);
    sk.k_2 = let_mpz_raw_to_str(k2.get_mpz_t());

    mpz_urandomb(k3.get_mpz_t(), rand_st, SECURITY_LEVEL);
    sk.k_3 = let_mpz_raw_to_str(k3.get_mpz_t());

    gmp_randclear(rand_st);

    return true;
}

/**
 * You know, cleaning up is a good habit.
 * Added since I used mpz_t, however mpz_class won't need them.
 * Thus ignore the following functions.
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
 * A wrapped JL scheme encryption alogrithm.
 * Yeah... the last one is the return value.. History....
*/
void JL_encryption(PK &pk, mpz_class &in, mpz_class &out)
{
#ifdef SEC_GDB_WITHOUT_ENCRYPTION
    out = in;
#else
    mpz_class seed;
    unsigned char rand_buff[KEY_SIZE] = {0};
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

    bhjl_encrypt(out.get_mpz_t(), in.get_mpz_t(), pk.jl_pk.N.get_mpz_t(),
                pk.jl_pk.y.get_mpz_t(), SECURITY_LEVEL, pk.jl_pk._2k.get_mpz_t(), rand_st);
    
    gmp_randclear(rand_st);
#endif
}

void JL_encryption(PK &pk, size_t num, mpz_class &out)
{
    mpz_class tmp(num);
    JL_encryption(pk, tmp, out);
}

/**
 * A wrapped JL scheme decryption alogrithm.
*/
void JL_decryption(SK &sk, PK &pk, mpz_class &in, mpz_class &out)
{
#ifdef SEC_GDB_WITHOUT_ENCRYPTION
    out = in;
#else
    bhjl_decrypt(out.get_mpz_t(), in.get_mpz_t(), sk.jl_sk.p.get_mpz_t(),pk.jl_pk.k.get_mpz_t(),
                    SECURITY_LEVEL, pk.jl_pk._2k1.get_mpz_t(), sk.jl_sk.pm12k.get_mpz_t());
#endif
}

void JL_decryption(SK &sk, PK &pk, mpz_class &in, size_t* out)
{
    mpz_class tmp;
    JL_decryption(sk, pk, in, tmp);
    *out = tmp.get_ui();
}

mpz_class JL_homo_add(PK &pk, mpz_class &left, mpz_class &right)
{
    mpz_class rtn;
#ifdef SEC_GDB_WITHOUT_ENCRYPTION
    rtn = left + right;
#else
    bhjl_homadd(rtn.get_mpz_t(), left.get_mpz_t(), right.get_mpz_t(), pk.jl_pk.N.get_mpz_t());
#endif
    return rtn;
}

mpz_class JL_homo_sub(PK &pk, mpz_class &left, mpz_class &right)
{
    mpz_class rtn;
#ifdef SEC_GDB_WITHOUT_ENCRYPTION
    rtn = left - right;
#else
    bhjl_homsub(rtn.get_mpz_t(), left.get_mpz_t(), right.get_mpz_t(), pk.jl_pk.N.get_mpz_t());
#endif
    return rtn;
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
    cout << sk.k_1.size();
    // fprintf(stdout, "\nsk.k_2: ");
    // // mpz_out_str(stdout, 10, sk.k_2);
    cout << sk.k_2.size();
    // fprintf(stdout, "\nsk.k_3: ");
    // // mpz_out_str(stdout, 10, sk.k_3);
    cout << sk.k_3.size();

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