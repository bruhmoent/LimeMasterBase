#ifndef SERVER_FLOW_MANAGEMENT_HPP
#define SERVER_FLOW_MANAGEMENT_HPP

#include <winsock2.h>
#include <string>
#include <chrono>
#include <memory>
#include <vector>
#include <algorithm>
#include "mysql_connection.h"
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <mutex>
#include <cppconn/prepared_statement.h>

class ServerFlowManagement {
public:
    ServerFlowManagement(SOCKET clientSocket, std::shared_ptr<sql::Connection> conn);
    ~ServerFlowManagement();
    void ProcessClient();
    void HandleFirstTimeConnection();
    void BroadcastMessageToClients(const std::string& username, const std::string& message, const std::string& timestamp);
    void SendPastMessages(int channelId);

private:
    SOCKET clientSocket;
    std::shared_ptr<sql::Connection> conn;
    static std::vector<SOCKET> clients;
    static std::mutex clientsMutex;

    std::string ReadMessage();
    void SendMessage(const std::string& message);
    void HandleMessage(const std::string& message, const std::string& username);
    bool AuthenticateUser(const std::string& credentials);
};

#endif // SERVER_FLOW_MANAGEMENT_HPP
