#ifndef SEC_GDB_H_GLOBAL
#define SEC_GDB_H_GLOBAL

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef SECURITY_LEVEL_128

#define SECURITY_LEVEL 128
#define KEY_SIZE 16

#else

#define SECURITY_LEVEL 256
#define KEY_SIZE 32

#endif

#define WRAPPING_GMP_EXPORT_FORMAT_ORDER     1   // The order is most significant word first
#define WRAPPING_GMP_EXPORT_FORMAT_SIZE      1   // The byte that a word represent
#define WRAPPING_GMP_EXPORT_FORMAT_ENDIAN    1   // For uniform use most significant byte first
#define WRAPPING_GMP_EXPORT_FORMAT_NAIL      0   // Asked to be 0

#define MAX_GGM_DEPTH 20

#define SCALE_SHIFT_P 16

#define INVERSE_ITERS 40

#define SEC_GDB_PAGE_RANK_D 0.85

typedef unsigned char BYTE;

// #define SEC_GDB_SIMPLE_MODE

// #define SEC_GDB_WITHOUT_ENCRYPTION

#define F_FUNCTION_DISABLE

#define MAX_EDGE_WEIGHT 10000
#define SEC_GDB_INF 1000000
#define EDGE_VALUE_SCALE 16 // Max value of edge is 2^EDGE_VALUE_SCALE

void log_memory(const void* ptr, size_t size);

#ifdef SEC_GDB_DBG
#include <stdio.h>
#include <stdarg.h>
#endif

static void log_dbg(const char* msg)
{
#ifdef SEC_GDB_DBG
    fprintf(stderr, "%s", msg);
#endif
}

static void log_dbg_fmt(const char* fmt, ...)
{
#ifdef SEC_GDB_DBG
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
#endif
}

#ifdef __cplusplus
}
#endif

#endif