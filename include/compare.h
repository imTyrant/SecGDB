#ifndef SEC_GDB_H_OBLIVC_COMPARE
#define SEC_GDB_H_OBLIVC_COMPARE

#define SEC_GDB_OBLIVC_SERVER 2
#define SEC_GDB_OBLIVC_PROXY 1

typedef int OBLIVC_DATA_TYPE;

typedef struct _OBLIVC_IO
{
    OBLIVC_DATA_TYPE a_1;
    OBLIVC_DATA_TYPE a_2;
    OBLIVC_DATA_TYPE r_1;
    OBLIVC_DATA_TYPE r_2;
    int result;
} OBLIVC_IO;

void compare(void* args);

#endif