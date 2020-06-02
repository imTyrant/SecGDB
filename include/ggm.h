#ifndef SEC_GDB_H_GGM
#define SEC_GDB_H_GGM

#ifdef __cplusplus
extern "C"
{
#endif

#include "global.h"

#define INT_MAX_VALUE ((int)~0)

typedef struct _GGM
{
    // int level;
    int key_size;
    int n;
    // char* key;
} GGM;

typedef struct _CONSTRAIN
{
    char* key;
    int depth;
    struct _CONSTRAIN* next;
} Constrain;

typedef struct _SUBKEYS
{
    char** keys;
    int num;
} Subkeys;

void ggm_find_best_range_cover(GGM *ggm, char *key, int start, int end, Constrain *constrain);

void ggm_free_constrain(Constrain *constrain);

void ggm_derive(GGM *ggm, Constrain *constrain, Subkeys *subkeys);

void ggm_free_keys(Subkeys *subkeys);

void print_constrain(Constrain* con, GGM* ggm);

#ifdef __cplusplus
}
#endif
#endif