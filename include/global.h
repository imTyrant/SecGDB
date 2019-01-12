#ifndef SEC_GDB_H_GLOBAL
#define SEC_GDB_H_GLOBAL

#ifdef __cplusplus
extern "C"
{
#endif

#define MAX_GGM_DEPTH 16

typedef unsigned char BYTE;

#ifdef SECURITY_LEVEL_128

#define SECURITY_LEVEL 128
#define KEY_SIZE 16

#else

#define SECURITY_LEVEL 256
#define KEY_SIZE 32

#endif

#ifdef __cplusplus
}
#endif

#endif