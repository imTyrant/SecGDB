#ifndef SEC_GDB_H_CLIENT
#define SEC_GDB_H_CLIENT

#include <string>
#include <gmpxx.h>
#include <unordered_map>

#include "global.h"
#include "graph.hpp"
#include "dictionary_items.hpp"
#include "crypto_stuff.hpp"

class Client
{
  private:
    SK sk;
    PK pk;
    Graph graph;

    // D_v which is outsourced to the proxy.
    // The key is raw char array contained by std::string.
    // The size should be KEY_SIZE defined in <global.h>.
    // During the initalization of the key, the size should be provided,
    // and it should KEY_SIZE. For example, std::string(XXX, KEY_SIZE);
    std::unordered_map<std::string, V_ITEM> D_pv; 
    
    // D_E
    // Both the key and the value are unreadable raw char array. So they should
    // be initalized like the key of D_pv.
    std::unordered_map<std::string, std::string> D_e; 

    // D_v' which is stored by the client.
    // Uhn... the key just is the name of vertex, just output is with cout.
    std::unordered_map<std::string, V_ITEM> D_cv; 

  public:
    Client();
    ~Client();

    void keygen();
    void enc_graph(const std::string &file_path);
    Request give_request(std::string src, std::string dest);

    void store_sk();
    void store_pk();

    void store_dpv();
    void store_dcv();
    void store_de();

    inline Graph& get_graph() { return this->graph; }

    inline SK& get_sk() { return this->sk; }

    inline PK& get_pk() { return this->pk; }

    inline const std::unordered_map<std::string, std::string> &get_De() const { return this->D_e; }

    inline const std::unordered_map<std::string, V_ITEM> &get_Dpv() const { return this->D_pv; }
};

#ifdef SEC_GDB_SIMPLE_MODE
extern Client g_client;
#endif

#endif