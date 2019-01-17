#ifndef SEC_GDB_H_OBLIVC_COMPARE
#define SEC_GDB_H_OBLIVC_COMPARE

#define OBLIVC_SERVER 1
#define OBLIVC_PROXY 2

typedef struct _OBLIVC_IO
{
    long long a_1;
    long long a_2;
    long long r_1;
    long long r_2;
    int result;
} OBLIVC_IO;

void compare(void* args);

#endif