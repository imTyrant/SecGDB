#ifndef SEC_GDB_H_INTERACTOR
#define SEC_GDB_H_INTERACTOR

#include <unordered_map>
#include <string>

#include "crypto_stuff.hpp"
#include "data_structures.hpp"

class Interactor
{
private:
    std::unordered_map<std::string, V_ITEM> D_pv;
    std::unordered_map<std::string, std::string> D_e; 
public:
    Interactor(/* args */);
    ~Interactor();

    void set_D_pv(const std::unordered_map<std::string, V_ITEM> &D_pv);
    void set_D_e(const std::unordered_map<std::string, std::string> D_e);
};



extern Interactor g_interactor;

#endif