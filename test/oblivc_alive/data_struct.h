#ifndef H_DATA_STRUCT
#define H_DATA_STRUCT

#define OBLIVC_PROXY 1
#define OBLIVC_SERVER 2

typedef struct _INPUT
{
    long long a_1;
    long long a_2;
    long long r_1;
    long long r_2;
    int result;
} INPUT;

void compare(void* args);

#endif