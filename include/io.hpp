#ifndef SEC_GDB_H_IO
#define SEC_GDB_H_IO

#include <unordered_map>
#include <boost/filesystem.hpp>
#include <string>
#include "data_structures.hpp"
#include "crypto_stuff.hpp"

bool save_pk(const boost::filesystem::path& p, const PK& pk);
bool save_pk(const std::string& file_path, const PK& pk);

bool save_sk(const boost::filesystem::path& p, const SK& sk);
bool save_sk(const std::string& file_path, const SK& sk);

bool load_pk(const boost::filesystem::path& p, PK& pk);
bool load_pk(const std::string& file_path, PK& pk);

bool load_sk(const boost::filesystem::path& p, SK& sk);
bool load_sk(const std::string& file_path, SK& sk);

bool save_De(const boost::filesystem::path& p, const std::unordered_map<std::string, std::string>& D_e);
bool save_De(const std::string& file_path, const std::unordered_map<std::string, std::string>& D_e);

bool save_Dv(const boost::filesystem::path& p, const std::unordered_map<std::string, V_ITEM>& D_v);
bool save_Dv(const std::string& file_path, const std::unordered_map<std::string, V_ITEM>& D_v);

bool load_Dv(const boost::filesystem::path& p, std::unordered_map<std::string, V_ITEM>& D_v);
bool load_Dv(const std::string& file_path, std::unordered_map<std::string, V_ITEM>& D_v);

bool load_De(const boost::filesystem::path& p, std::unordered_map<std::string, std::string>& D_e);
bool load_De(const std::string& file_path, std::unordered_map<std::string, std::string>& D_e);

#endif // SEC_GDB_H_IO