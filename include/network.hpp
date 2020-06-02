#ifndef SEC_GDB_H_NETWORK
#define SEC_GDB_H_NETWORK

#include <string>
#include <boost/asio.hpp>
#include <gmpxx.h>

#include "ggm.h"

/* Protocol head for network */
typedef char PROTOCOL_HEAD_TYPE;

const PROTOCOL_HEAD_TYPE MPC_EMPTY_PROTOCOL = 0x0;
const PROTOCOL_HEAD_TYPE MPC_SECURE_COMPARSION = 0x1;
const PROTOCOL_HEAD_TYPE MPC_SECURE_MULTIPLICATION = 0x2;
const PROTOCOL_HEAD_TYPE MPC_SECURE_INVERSE = 0x3;
const PROTOCOL_HEAD_TYPE MPC_LOOK_UP = 0x4;

/* Default value */
const short PORT = 23333;
const char* const ADDRESS = "127.0.0.1";

/* Exception for network */
class sec_gdb_network_exception: public std::exception
{
private:
    std::string err_msg;
    int err_code;
public:
    sec_gdb_network_exception(const std::string& em="", int ec=0)
        : err_msg(em), err_code(ec)
    {
    }
    const std::string& get_msg() const
    {
        return this->err_msg;
    }
    int get_ec() const
    {
        return this->err_code;
    }
    const char* what()
    {
        std::string msg("Error: ");
        msg += err_msg;
        msg += " Error code: ";
        msg += std::to_string(err_code);
        return msg.c_str();
    }
};

/* Functions fro network */
int net_recv_sized_data(boost::asio::ip::tcp::socket& sock, char* &buff);
bool net_send_sized_data(boost::asio::ip::tcp::socket& sock, int size, char* buff);

bool net_recv_mpz_class(boost::asio::ip::tcp::socket& sock, mpz_class& out);
bool net_send_mpz_class(boost::asio::ip::tcp::socket& sock, mpz_class& in);

bool net_recv_constrain(boost::asio::ip::tcp::socket& sock, GGM& ggm, Constrain& con, int& ctr);
bool net_send_constrain(boost::asio::ip::tcp::socket& sock, GGM& ggm, Constrain& con, int ctr);

char net_recv_protocol_head(boost::asio::ip::tcp::socket& sock);
void net_send_protocol_head(boost::asio::ip::tcp::socket& sock, PROTOCOL_HEAD_TYPE protocol);

extern size_t g_protocol_ctr;

#endif //SEC_GDB_H_NETWORK