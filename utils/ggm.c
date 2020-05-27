#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "ggm.h"
#include "global.h"

void log_error()
{
    ERR_print_errors((BIO *)stderr);
    abort();
}

/*
 * Key extension fucntion.
 * Assume all the memeory has been alloced!
 * 
 * Input: 
 *      [in]GGM* ggm: the init parametet.
 *      [in]char* in: a input key size.
 *      [out]char* out_left: return left part of extend keys;
 *      [out]char* out_right: return right part of extend keys;
 */
void GFunction(GGM *ggm, char *in, char *out_left, char *out_right)
{
#ifdef GGM_DBG
    int n = strlen(in);
    strcpy(out_left, in);
    strcpy(out_right, in);
    if (n < ggm->key_size)
    {
        strcat(out_left, "0");
        strcat(out_right, "1");
    }
#elif defined SECURITY_LEVEL_128
    EVP_CIPHER_CTX *ctx;
    int len_l;
    int len_r;

    int clen_l;
    int clen_r;

    unsigned char left_data[KEY_SIZE];
    unsigned char right_data[KEY_SIZE];

    SHA1("0", 2, left_data);
    SHA1("1", 2, right_data);

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        log_error();
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, (unsigned char*)in, (unsigned char*)in))
    {
        log_error();
    }

    if (1 != EVP_EncryptUpdate(ctx, (unsigned char *)out_left, &len_l, left_data, KEY_SIZE))
    {
        log_error();
    }
    clen_l = len_l;
    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char *)out_left, &len_l))
    {
        log_error();
    }
    clen_l += len_l;

    if (1 != EVP_EncryptUpdate(ctx, (unsigned char *)out_right, &len_r, right_data, KEY_SIZE))
    {
        log_error();
    }
    clen_r = len_r;
    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char *)out_right, &len_r))
    {
        log_error();
    }
    clen_r += len_r;

    EVP_CIPHER_CTX_free(ctx);

#else
    EVP_CIPHER_CTX *ctx;
    int len_l;
    int len_r;

    int clen_l;
    int clen_r;
    
    unsigned char left_data[KEY_SIZE];
    unsigned char right_data[KEY_SIZE];

    SHA256("0", 2, left_data);
    SHA256("1", 2, right_data);

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        log_error();
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, (unsigned char*)in, (unsigned char*)in))
    {
        log_error();
    }

    if (1 != EVP_EncryptUpdate(ctx, (unsigned char *)out_left, &len_l, left_data, KEY_SIZE))
    {
        log_error();
    }
    clen_l = len_l;
    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char *)out_left, &len_l))
    {
        log_error();
    }
    clen_l += len_l;

    if (1 != EVP_EncryptUpdate(ctx, (unsigned char *)out_right, &len_r, right_data, KEY_SIZE))
    {
        log_error();
    }
    clen_r = len_r;
    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char *)out_right, &len_r))
    {
        log_error();
    }
    clen_r += len_r;

    EVP_CIPHER_CTX_free(ctx);
#endif
}

/*
 * The key extenstion function.
 * Input:
 *      [in]GGM* ggm: the init parameter.
 *      [in]char* key: the orignal key which used to extent the sub-key.
 *      [in]int x: the selector of sub-key, bit-0 for left, bit-1 for right.
 *      [in]int length: the left depth to be generate.
 *      [out]char* out: the final sub-key.
 */
void FkFunction(GGM *ggm, char *key, int x, int length, char *out)
{
    char *tmp = key;

    int n = ggm->n;
    int mask = 0b1 << (n - 1);

    char left[ggm->key_size], right[ggm->key_size];

    for (int i = 0; i < length; i++)
    {

        GFunction(ggm, tmp, left, right);
        if (((mask >> i) & x) == 0)
        {
            tmp = left;
        }
        else
        {
            tmp = right;
        }
    }

    memcpy(out, tmp, ggm->key_size);
}

/*
 * Find the the highest different bit between start and end.
 * Input:
 *      GGM* ggm: the init parameter.
 *      int start: the start index.
 *      int end: the end index.
 * Return:
 *      int: the highest same bit between. 
 *          (count from 0, so 3 means the highest bit is 4th
 *          e.g. 0001, 0101 -> 2
*/
int compare_bit(GGM *ggm, int start, int end)
{
    int same = start ^ end;
    int mask = 0b1;
    int max = 0;

    for (int i = 0; i < (ggm->n); i++)
    {
        if (((same >> i) & mask) != 0)
        {
            max = i;
        }
    }
    return max;
}

void add_constrain(GGM *ggm, Constrain *rtn, char *key, int x, int length, int depth)
{
    rtn->depth = depth;
    rtn->key = (char *)malloc(ggm->key_size);
    FkFunction(ggm, key, x, length, rtn->key);
}

/**
 * Find the best range cover of ggm.
 * Assume all of pointers have been alloced memory.
 * 
 * Input:
 *      [in]GGM* ggm: the inti parameter.
 *      [in]char* key: the main key used to generate sub-keys.
 *      [in]int start: the start postion of range.
 *      [end]int end: the end postion of range.
 *      [out]Constrain *constrain: output the constrain.
*/
void ggm_find_best_range_cover(GGM *ggm, char *key, int start, int end, Constrain *constrain)
{
    int t = compare_bit(ggm, start, end);
    int same_part_mask = ~(INT_MAX_VALUE << t);

    Constrain *rtn = constrain;

    if (start == end)
    {
        add_constrain(ggm, rtn, key, start, ggm->n, t);
        rtn->next = NULL;
        return;
    }

    if ((same_part_mask & start) == 0)
    {
        if (((same_part_mask & end) ^ same_part_mask) == 0)
        {
            add_constrain(ggm, rtn, key, start, (ggm->n - t - 1), t + 1);
            rtn->next = NULL;
            return;
        }
        else
        {
            add_constrain(ggm, rtn, key, start, (ggm->n - t), t);
            rtn->next = (Constrain *)malloc(sizeof(Constrain));
            rtn = rtn->next;
        }
    }
    else
    {
        int u = t;
        for (int i = 0; i <= t; i++)
        {
            if (((start >> i) & 0b1) == 0b1)
            {
                u = i;
                break;
            }
        }

        add_constrain(ggm, rtn, key, start, (ggm->n - u), u);
        rtn->next = (Constrain *)malloc(sizeof(Constrain));
        rtn = rtn->next;

        // for (int j = t - 1; j >= u + 1; j--)
        for (int j = u + 1; j <= t - 1; j++)
        {
            if (((start >> j) & 0b1) == 0b0)
            {
                add_constrain(ggm, rtn, key, (start | (0b1 << j)), (ggm->n - j), j);
                rtn->next = (Constrain *)malloc(sizeof(Constrain));
                rtn = rtn->next;
            }
        }
    }

    if (((same_part_mask & end) ^ same_part_mask) == 0)
    {
        add_constrain(ggm, rtn, key, end, (ggm->n - t), t);
        rtn->next = (Constrain *)malloc(sizeof(Constrain));
        rtn = rtn->next;
    }
    else
    {
        int v = t;
        for (int i = 0; i <= t; i++)
        {
            if (((end >> i) & 0b1) == 0)
            {
                v = i;
                break;
            }
        }
        for (int j = t - 1; j >= v + 1; j--)
        {
            if (((end >> j) & 0b1) == 0b1)
            {
                add_constrain(ggm, rtn, key, (end & (INT_MAX_VALUE ^ (0b1 << j))), (ggm->n - j), j);
                rtn->next = (Constrain *)malloc(sizeof(Constrain));
                rtn = rtn->next;
            }
        }
        add_constrain(ggm, rtn, key, end, (ggm->n - v), v);
        rtn->next = NULL;
    }
}

/**
 * Free alloced memory of Constrain.
 * The first one will not be free!!
 * 
 * Input:
 *      [in]Constrain *constrain: the constrain needed to be free.
*/
void ggm_free_constrain(Constrain *constrain)
{

    free(constrain->key);

    Constrain *rtn = constrain->next;

    while (rtn != NULL)
    {
        Constrain *tmp = rtn->next;
        free(rtn->key);
        free(rtn);
        rtn = tmp;
    }
}

void derive_sub(GGM *ggm, char *key, char **dest, int depth)
{
    if (depth == 0)
    {
        memcpy(*dest, key, ggm->key_size);
        return;
    }

    char left[ggm->key_size], right[ggm->key_size];

    GFunction(ggm, key, left, right);

    derive_sub(ggm, left, dest, depth - 1);
    derive_sub(ggm, right, (dest + (int)pow(2, depth - 1)), depth - 1);
}

/**
 * Derive all of subkey from the give constrain.
 * Input:
 *      [in] GGM* ggm: the intial parameter of GGM.
 *      [in] Constrain* constrain: the given constrain.
 *      [out] Subkeys* subkeys: a structure which is used to put
 *              all of subkeys.
 */
void ggm_derive(GGM *ggm, Constrain *constrain, Subkeys *subkeys)
{
    Constrain *tmp = constrain;
    int total_key_size = 0;
    //Get total size of key.
    while (tmp != NULL)
    {
        total_key_size += (int)pow(2, tmp->depth);
        tmp = tmp->next;
    }
    tmp = constrain;
    //malloc memory of keys.
    subkeys->keys = (char **)malloc(sizeof(char *) * total_key_size);
    for (int i = 0; i < total_key_size; i++)
    {
        (subkeys->keys)[i] = (char *)malloc(sizeof(char) * ggm->key_size);
    }

    int j = 0;
    while (tmp != NULL)
    {
        derive_sub(ggm, tmp->key, &((subkeys->keys)[j]), tmp->depth);
        j += (int)pow(2, tmp->depth);
        tmp = tmp->next;
    }
    subkeys->num = total_key_size;
}

/**
 * Clean up all of subkeys
 * Input:
 *      [in] Subkey *subkeys: you know, stuffs need to be clean.
 */
void ggm_free_keys(Subkeys *subkeys)
{
    for(int i = 0; i < subkeys->num; i++)
    {
        free((subkeys->keys)[i]);
    }
    
    free(subkeys->keys);
}