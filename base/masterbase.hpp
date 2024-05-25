#include <ws2tcpip.h>
#include <iostream>
#include <Windows.h>
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <cppconn/exception.h>
#include <thread>
#include <memory>

#ifndef MASTERBASE_HPP
#define MASTERBASE_HPP


class MasterBase {
private:
    SOCKET serverSocket;
    std::shared_ptr<sql::Connection> conn;
    sql::Driver* driver;

    void InitializeNetworking();
    void InitializeDatabase();
    

public:
    MasterBase();
    ~MasterBase();
    void WaitForClientConnection();
};

#endif // MASTERBASE_HPP
