#ifndef SEC_GDB_H_EXCEPTION
#define SEC_GDB_H_EXCEPTION

#include <exception>

class sec_gdb_global_exception: public std::exception
{
private:
    const char* em;
public:
    sec_gdb_global_exception(const char* msg)
        : em(msg)
    {
    }
    const char* get_msg() const 
    {
        return this->em;
    }

    const char* what()
    {
        return this->em;
    }
};

#endif // SEC_GDB_H_EXCEPTION