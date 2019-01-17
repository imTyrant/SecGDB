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

typedef unsigned char BYTE;

#define SEC_GDB_SIMPLE_MODE

#define SEC_GDB_WITHOUT_ENCRYPTION

void log_memory(const void* ptr, size_t size);

#ifdef __cplusplus
}
#endif

#endif