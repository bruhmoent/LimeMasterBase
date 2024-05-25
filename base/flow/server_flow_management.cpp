#include "server_flow_management.hpp"
#include <iostream>
#include <sstream>
#include <thread>
#include <mutex>
#include <ctime>
#include <iomanip>

std::vector<SOCKET> ServerFlowManagement::clients;
std::mutex ServerFlowManagement::clientsMutex;

ServerFlowManagement::ServerFlowManagement(SOCKET clientSocket, std::shared_ptr<sql::Connection> conn)
    : clientSocket(clientSocket), conn(conn) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    clients.push_back(clientSocket);
}

ServerFlowManagement::~ServerFlowManagement() {
    std::lock_guard<std::mutex> lock(clientsMutex);
    clients.erase(std::remove(clients.begin(), clients.end(), clientSocket), clients.end());
    closesocket(clientSocket);
}

std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    size_t end = str.find_last_not_of(" \t\r\n");

    if (start == std::string::npos || end == std::string::npos) {
        return "";
    }

    return str.substr(start, end - start + 1);
}

std::string ServerFlowManagement::ReadMessage() {
    char buffer[4096];
    ZeroMemory(buffer, 4096);
    int bytesReceived = recv(clientSocket, buffer, 4096, 0);
    if (bytesReceived == SOCKET_ERROR) {
        std::cerr << "Error in recv(). Quitting" << std::endl;
        return "";
    }
    if (bytesReceived == 0) {
        std::cout << "Client disconnected" << std::endl;
        return "";
    }

    std::string receivedMessage(buffer, bytesReceived);

    // Trim leading and trailing whitespace
    receivedMessage = trim(receivedMessage);

    if (receivedMessage.empty()) {
        return "";
    }

    return receivedMessage;
}

void ServerFlowManagement::SendMessage(const std::string& message) {
    std::string messageWithDelimiter = message + "\n";
    send(clientSocket, messageWithDelimiter.c_str(), messageWithDelimiter.size(), 0);
}

void ServerFlowManagement::HandleMessage(const std::string& message, const std::string& username) {
    try {
        // Retrieve the user_id based on the username
        sql::PreparedStatement* pstmt = conn->prepareStatement("SELECT user_id FROM Users WHERE username = ?");
        pstmt->setString(1, username);
        sql::ResultSet* res = pstmt->executeQuery();
        res->next();
        int userId = res->getInt("user_id");
        delete pstmt;
        delete res;

        int channelId = 1;
        pstmt = conn->prepareStatement("INSERT INTO Messages (channel_id, user_id, content) VALUES (?, ?, ?)");
        pstmt->setInt(1, channelId);
        pstmt->setInt(2, userId);
        pstmt->setString(3, message);
        pstmt->execute();
        delete pstmt;

        // Get the current timestamp
        auto now = std::chrono::system_clock::now();
        std::time_t nowTime = std::chrono::system_clock::to_time_t(now);
        std::tm nowTm;
        localtime_s(&nowTm, &nowTime);
        std::ostringstream oss;
        oss << std::put_time(&nowTm, "%Y-%m-%d %H:%M");

        BroadcastMessageToClients(username, message, oss.str());
    }
    catch (sql::SQLException& e) {
        std::cerr << "SQLException: " << e.what() << std::endl;
        std::cerr << "SQLState: " << e.getSQLState() << std::endl;
    }
}

void ServerFlowManagement::BroadcastMessageToClients(const std::string& username, const std::string& message, const std::string& timestamp) {
    std::string fullMessage = "[" + timestamp + "] <" + username + ">: " + message;
    std::lock_guard<std::mutex> lock(clientsMutex);

    for (const auto& client : clients) {
        if (client != clientSocket) {
            send(client, (fullMessage + "\n").c_str(), fullMessage.size() + 1, 0);
        }
    }
}

bool ServerFlowManagement::AuthenticateUser(const std::string& credentials) {
    std::istringstream iss(credentials);
    std::string messageContent, username, password;
    std::getline(iss, messageContent, '|');
    std::getline(iss, username, '|');
    std::getline(iss, password);

    try {
        // Check if the user exists in the database
        sql::PreparedStatement* pstmt = conn->prepareStatement("SELECT password FROM Users WHERE username = ?");
        pstmt->setString(1, username);
        sql::ResultSet* res = pstmt->executeQuery();

        if (res->next()) {
            // User exists, validate password
            std::string storedPasswordHash = res->getString("password");
            delete pstmt;
            delete res;

            if (storedPasswordHash == password) {
                // Authentication successful
                SendMessage("Authentication successful");
                return true;
            }
            else {
                // Invalid password
                return false;
            }
        }
        else {
            // User doesn't exist, create a new user
            delete pstmt;
            delete res;

            pstmt = conn->prepareStatement("INSERT INTO Users (username, password) VALUES (?, ?)");
            pstmt->setString(1, username);
            pstmt->setString(2, password);
            pstmt->execute();
            delete pstmt;

            // Authentication successful
            SendMessage("Authentication successful");
            return true;
        }
    }
    catch (sql::SQLException& e) {
        std::cerr << "SQLException: " << e.what() << std::endl;
        std::cerr << "SQLState: " << e.getSQLState() << std::endl;
        return false;
    }
}

void ServerFlowManagement::ProcessClient() {
    HandleFirstTimeConnection();

    while (true) {
        std::string message = ReadMessage();
        if (message.empty()) {
            break;
        }

        // Assume the first message is the authentication message
        if (!AuthenticateUser(message)) {
            SendMessage("Authentication failed. Please try again.");
            continue;
        }

        // Authentication succeeded, handle subsequent messages
        while (true) {
            std::string userMessage = ReadMessage();
            if (userMessage.empty()) {
                break;
            }

            // If it's a past message request, handle it separately
            if (userMessage.find("GET_PAST_MESSAGES|") == 0) {
                int channelId = std::stoi(userMessage.substr(userMessage.find('|') + 1));
                SendPastMessages(channelId);
            }
            else {
                std::string username = message.substr(message.find('|') + 1, message.rfind('|') - message.find('|') - 1);
                HandleMessage(userMessage, username);
            }
        }
    }
}

void ServerFlowManagement::HandleFirstTimeConnection() {
    SendMessage("Welcome to the chat server!");
}

void ServerFlowManagement::SendPastMessages(int channelId) {
    try {
        // Prepare a SQL statement to retrieve messages for the specified channel
        sql::PreparedStatement* pstmt = conn->prepareStatement(
            "SELECT Users.username, Messages.content, Messages.created_at "
            "FROM Messages "
            "JOIN Users ON Messages.user_id = Users.user_id "
            "WHERE Messages.channel_id = ? "
            "ORDER BY Messages.created_at ASC"
        );
        pstmt->setInt(1, channelId);

        // Execute the query
        sql::ResultSet* res = pstmt->executeQuery();

        // Iterate through the results and send each message to the client
        while (res->next()) {
            std::string username = res->getString("username");
            std::string content = res->getString("content");
            std::string createdAt = res->getString("created_at");

            // Convert createdAt to a more readable format
            std::tm createdAtTm = {};
            std::istringstream ss(createdAt);
            ss >> std::get_time(&createdAtTm, "%Y-%m-%d %H:%M:%S");
            std::ostringstream formattedTimestamp;
            formattedTimestamp << std::put_time(&createdAtTm, "%Y-%m-%d %H:%M");

            std::string fullMessage = "[" + formattedTimestamp.str() + "] <" + username + ">: " + content;
            SendMessage(fullMessage);
        }

        delete res;
        delete pstmt;
    }
    catch (sql::SQLException& e) {
        std::cerr << "SQLException: " << e.what() << std::endl;
        std::cerr << "SQLState: " << e.getSQLState() << std::endl;
    }
}
