#include <iostream>
#include <fstream>
#include <iostream>
#include <string>
#include <cstdio>
#include <gmp.h>
#include <gmpxx.h>
#include <boost/filesystem.hpp>

#include "nlohmann/json.hpp"

#include "crypto_stuff.hpp"
#include "data_structures.hpp"
#include "io.hpp"

using namespace std;
namespace fs = boost::filesystem;

using json = nlohmann::json;

string raw_to_hex(const string& raw)
{
    int n = raw.size();
    char buff[2 * n + 1];
    const unsigned char* tmp = reinterpret_cast<const unsigned char*>(raw.c_str());
    for (int i = 0; i < n; i ++)
    {
        sprintf(buff + 2 * i, "%02x", tmp[i]);
    }
    return string(buff);
}

string hex_to_raw(const string& hex)
{
    int n = hex.size();
    unsigned char buff[n / 2];
    for (int i = 0; i < n; i += 2)
    {
        sscanf((hex.c_str() + i), "%2hhx", &buff[i/2]);
    }
    return string((char*)buff, n / 2);
}

void check_create(const fs::path& p)
{
    mpz_class a;
    if (!fs::exists(p))
    {
        fs::create_directories(p.parent_path());
    }
}

bool save_pk(const fs::path& p, const PK& pk)
{
    check_create(p);
    ofstream os(p.string(), ofstream::out);
    json j;
    j["jl_pk"]["k"] = pk.jl_pk.k.get_str();
    j["jl_pk"]["N"] = pk.jl_pk.N.get_str();
    j["jl_pk"]["y"] = pk.jl_pk.y.get_str();
    j["jl_pk"]["_2k1"] = pk.jl_pk._2k1.get_str();
    j["jl_pk"]["_2k"] = pk.jl_pk._2k.get_str();
    os << j.dump() << endl;
    os.close();
    return true;
}

bool save_pk(const string& file_path, const PK& pk)
{
    return save_pk(fs::path(file_path), pk);
}

bool save_sk(const fs::path& p, const SK& sk)
{
    check_create(p);
    ofstream os(p.string(), ofstream::out);
    json j;
    j["jl_sk"]["p"] = sk.jl_sk.p.get_str();
    j["jl_sk"]["pm12k"] = sk.jl_sk.pm12k.get_str();
    j["k_1"] = raw_to_hex(sk.k_1);
    j["k_2"] = raw_to_hex(sk.k_2);
    j["k_3"] = raw_to_hex(sk.k_3);
    os << j.dump() << endl;
    os.close();
    return true;
}

bool save_sk(const string& file_path, const SK& sk)
{
    return save_sk(fs::path(file_path), sk);
}

bool load_pk(const fs::path& p, PK& pk)
{
    if (!fs::exists(p)) { return false; }
    json j;
    ifstream is(p.string(), ios::in);
    is >> j;
    pk.jl_pk.k = mpz_class(j["jl_pk"]["k"].get<string>(), 10);
    pk.jl_pk.N = mpz_class(j["jl_pk"]["N"].get<string>(), 10);
    pk.jl_pk.y = mpz_class(j["jl_pk"]["y"].get<string>(), 10);
    pk.jl_pk._2k1 = mpz_class(j["jl_pk"]["_2k1"].get<string>(), 10);
    pk.jl_pk._2k = mpz_class(j["jl_pk"]["_2k"].get<string>(), 10);
    is.close();
    return true;
}

bool load_pk(const string& file_path, PK& pk)
{
    return load_pk(fs::path(file_path), pk);
}

bool load_sk(const fs::path& p, SK& sk)
{
    if (!fs::exists(p)) { return false; }
    json j;
    ifstream is(p.string(), ios::in);
    is >> j;

    sk.jl_sk.p = mpz_class(j["jl_sk"]["p"].get<string>(), 10);
    sk.jl_sk.pm12k = mpz_class(j["jl_sk"]["pm12k"].get<string>(), 10);
    sk.k_1 = hex_to_raw(j["k_1"].get<string>());
    sk.k_2 = hex_to_raw(j["k_2"].get<string>());
    sk.k_3 = hex_to_raw(j["k_3"].get<string>());
    
    is.close();
    return true;
}

bool load_sk(const string& file_path, SK& sk)
{
    return load_sk(fs::path(file_path), sk);
}


bool save_De(const fs::path& p, const unordered_map<string, string>& D_e)
{
    check_create(p);
    ofstream os(p.string(), ofstream::out | ofstream::binary);

    size_t size = D_e.size();
    os.write(reinterpret_cast<char*>(&size), sizeof(size_t));
    for (auto it = D_e.begin(); it != D_e.end(); it++)
    {
        size_t bytes_num = it->first.size();
        os.write(reinterpret_cast<char*>(&bytes_num), sizeof(size_t));
        os.write(it->first.c_str(), bytes_num);

        bytes_num = it->second.size();
        os.write(reinterpret_cast<char*>(&bytes_num), sizeof(size_t));
        os.write(it->second.c_str(), bytes_num);
    }
    os.close();
    return true;
}

bool save_De(const string& file_path, const unordered_map<string, string>& D_e)
{
    return save_De(fs::path(file_path), D_e);
}

bool save_Dv(const fs::path& p, const unordered_map<std::string, V_ITEM>& D_v)
{
    check_create(p);
    ofstream os(p.string(), ofstream::binary | ofstream::out);
    size_t size = D_v.size();
    os.write(reinterpret_cast<char*>(&size), sizeof(size_t));
    for (auto it = D_v.begin(); it != D_v.end(); it++)
    {
        size_t bytes_num = it->first.size();
        os.write(reinterpret_cast<char*>(&bytes_num), sizeof(size_t));
        os.write(it->first.c_str(), bytes_num);

        os.write(reinterpret_cast<char*>(const_cast<size_t*>(&it->second.ctr)), sizeof(size_t));

        bytes_num = it->second.master_key.size();
        os.write(reinterpret_cast<char*>(&bytes_num), sizeof(size_t));
        os.write(it->second.master_key.c_str(), bytes_num);
    }
    os.close();
    return true;
}

bool save_Dv(const string& file_path, const unordered_map<std::string, V_ITEM>& D_v)
{
    return save_Dv(fs::path(file_path), D_v);
}

bool load_Dv(const fs::path& p, unordered_map<std::string, V_ITEM>& D_v)
{
    if (!fs::exists(p)) { return false; }
    ifstream is(p.string(), ifstream::in | ifstream::binary);
    
    is.seekg(0, is.end);
    size_t length = is.tellg();
    is.seekg(0, is.beg);

    char* buff = new char[length];
    char* tmp = buff;

    is.read(buff, length);
    int size = *reinterpret_cast<size_t*>(tmp);
    tmp += sizeof(size_t);
    for (int i = 0; i < size; i ++)
    {
        int key_len = *reinterpret_cast<size_t*>(tmp);
        tmp += sizeof(size_t);
        string key(tmp, key_len);
        tmp += key_len;

        size_t ctr = *reinterpret_cast<size_t*>(tmp);
        tmp += sizeof(size_t);

        int masterkey_len = *reinterpret_cast<size_t*>(tmp);
        tmp += sizeof(size_t);
        string masterkey(tmp, masterkey_len);
        tmp += masterkey_len;

        D_v[key] = {ctr, masterkey};
    }

    delete buff;
    return true;
}

bool load_Dv(const string& file_path, unordered_map<string, V_ITEM>& D_v)
{
    return load_Dv(fs::path(file_path), D_v);
}

bool load_De(const fs::path& p, unordered_map<string, string>& D_e)
{
    if (!fs::exists(p)) { return false; }
    ifstream is(p.string(), ifstream::in | ifstream::binary);
    
    is.seekg(0, is.end);
    size_t length = is.tellg();
    is.seekg(0, is.beg);

    char* buff = new char[length];
    char* tmp = buff;

    is.read(buff, length);
    int size = *reinterpret_cast<size_t*>(tmp);
    tmp += sizeof(size_t);
    for (int i = 0; i < size; i ++)
    {
        int key_len = *reinterpret_cast<size_t*>(tmp);
        tmp += sizeof(size_t);
        string key(tmp, key_len);
        tmp += key_len;

        int value_len = *reinterpret_cast<size_t*>(tmp);
        tmp += sizeof(size_t);
        string value(tmp, value_len);
        tmp += value_len;

        D_e[key] = value;
    }

    delete buff;
    return true;    
}


bool load_De(const string& file_path, unordered_map<string, string>& D_e)
{
    return load_De(fs::path(file_path), D_e);
}
