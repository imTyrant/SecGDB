#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#include "ggm.h"
#include "global.h"

#include <openssl/sha.h>
#include <openssl/conf.h>

void sha(char *in, int size, char *out)
{
#if defined SECURITY_LEVEL_128
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, in, size);
    SHA1_Final(out, &ctx);
#else
    SHA256((unsigned char*)in, (size_t)size, (unsigned char*)out);
#endif
}

int main(int argc, char **argv)
{
    int start, end;
    GGM ggm;

    ggm.key_size = KEY_SIZE;

#ifdef GGM_DBG
    char *key = "key";
#else
    char key[KEY_SIZE];
    char *random = "God damn who knows what key is....";
    sha(random, strlen(random), key);
#endif

    if (argc == 4)
    {
        ggm.n = strtol(argv[1], NULL, 10);
        // ggm.level = ggm.n + 1;

        start = strtol(argv[2], NULL, 10);
        end = strtol(argv[3], NULL, 10);
    }
    else
    {   
        ggm.n = 5;
        // ggm.level = ggm.n;

        start = 1;
        end = 2;
        // end = (int)pow(2, ggm.n) - 2;
    }

    Constrain constrain = {0};
    
    ggm_find_best_range_cover(&ggm, key, start, end, &constrain);
    Constrain *rtn = &constrain;
    while (rtn != NULL)
    {

#ifdef GGM_DBG
        printf("%s ", rtn->key);
#else
        BIO_dump_fp(stdout, (const char *)(rtn->key), ggm.key_size);
#endif
        printf("level left: %d\n\n", rtn->depth);
        rtn = rtn->next;
    }

    Subkeys subkeys = {0};

    ggm_derive(&ggm, &constrain, &subkeys);

    for (int i = 0; i < subkeys.num; i++)
    {
#ifdef GGM_DBG
        printf("%s\n", subkeys.keys[i]);
#else
        BIO_dump_fp(stdout, (const char *)(subkeys.keys[i]), ggm.key_size);
#endif
    }

    ggm_free_keys(&subkeys);

    ggm_free_constrain(&constrain);

    return 0;
}