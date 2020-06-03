#ifndef SEC_GDB_H_CLIENT
#define SEC_GDB_H_CLIENT

#include <string>
#include <gmpxx.h>
#include <unordered_map>
#include <utility>

#include "global.h"
#include "graph.hpp"
#include "data_structures.hpp"
#include "crypto_stuff.hpp"
#include "io.hpp"

class Client
{
  private:
    SK sk;
    PK pk;
    Graph<size_t> graph;

    // D_v which is outsourced to the proxy.
    // The key is raw char array contained by std::string.
    // The size should be KEY_SIZE defined in <global.h>.
    // During the initialization of the key, the size should be provided,
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
    void enc_graph(const std::string &file_path, int scaler=0);
    Request give_request(std::string src, std::string dest);
    void update_graph(const std::string &src, const std::string &dest, const size_t weight, int op);

    void store_sk(const std::string& filePath) const { if (!save_sk(filePath, this->sk)) { std::cerr << "Saving sk failed." << std::endl; } };
    void read_sk(const std::string& filePath) { if (!load_sk(filePath, this->sk)) { std::cerr << "Loading sk failed." << std::endl; } };
    void store_pk(const std::string& filePath) const { if (!save_pk(filePath, this->pk)) { std::cerr << "Saving pk failed." << std::endl; } };
    void read_pk(const std::string& filePath) { if (!load_pk(filePath, this->pk)) { std::cerr << "Loading pk failed." << std::endl; } };

    void save_dpv(const std::string &filePath);
    void load_dpv(const std::string &filePath);
    void save_dcv(const std::string &filePath);
    void load_dcv(const std::string &filePath);
    void save_de(const std::string &filePath);
    void load_de(const std::string &filePath);

    inline void clean_up()
    {
      this->graph.clear();
      this->D_cv.clear();
      this->D_pv.clear();
      this->D_e.clear();
    }

    inline void set_keys(const PK& pk, const SK& sk)
    {
      this->pk = pk;
      this->sk = sk;
    }

    inline Graph<size_t>& get_graph() { return this->graph; }

    inline SK& get_sk() { return this->sk; }

    inline PK& get_pk() { return this->pk; }

    inline const std::unordered_map<std::string, std::string> &get_De() const { return this->D_e; }

    inline void set_De(std::unordered_map<std::string, std::string> &&D_e) { this->D_e = std::forward<std::unordered_map<std::string, std::string>>(D_e); }

    inline const std::unordered_map<std::string, V_ITEM> &get_Dpv() const { return this->D_pv; }

    inline void set_Dpv(std::unordered_map<std::string, V_ITEM> &&D_pv) { this->D_pv = std::forward<std::unordered_map<std::string, V_ITEM>>(D_pv); }
    
    inline const std::unordered_map<std::string, V_ITEM> &get_Dcv() const { return this->D_cv; }

    inline void set_Dcv(std::unordered_map<std::string, V_ITEM> &&Dcv) { this->D_cv = std::forward<std::unordered_map<std::string, V_ITEM>>(D_cv); }
};

#ifdef SEC_GDB_DBG
extern Client dbg_client;
#endif

#ifdef SEC_GDB_SIMPLE_MODE
extern Client g_client;
#endif
extern double g_c_update_clt;
extern double g_c_update_srv;
extern double g_c_update_prxy;

#endif