#include "masterbase.hpp"
#include "flow/server_flow_management.hpp"

#pragma comment(lib, "ws2_32.lib")

MasterBase::MasterBase() {
    InitializeNetworking();
    InitializeDatabase();
}

MasterBase::~MasterBase() {
    closesocket(serverSocket);
    WSACleanup();
    conn->close();
}

void MasterBase::InitializeNetworking() {
    WSADATA wsData;
    WORD ver = MAKEWORD(2, 2);
    int wsResult = WSAStartup(ver, &wsData);
    if (wsResult != 0) {
        std::cerr << "Can't start Winsock, Err #" << wsResult << std::endl;
        exit(1);
    }

    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Can't create socket, Err #" << WSAGetLastError() << std::endl;
        WSACleanup();
        exit(1);
    }

    SOCKADDR_IN serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(54000);
    inet_pton(AF_INET, "192.168.1.169", &serverAddr.sin_addr);

    if (bind(serverSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed, Err #" << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        exit(1);
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed, Err #" << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        exit(1);
    }

    std::cout << "Server started. Waiting for client connection..." << std::endl;
}

void MasterBase::InitializeDatabase() {
    try {
        driver = sql::mysql::get_mysql_driver_instance();
        conn = std::shared_ptr<sql::Connection>(driver->connect("tcp://192.168.1.169:3306", "username", "password"));

        conn->setSchema("limechatmasterbase");

        std::cout << "Database connected." << std::endl;
    }
    catch (sql::SQLException& e) {
        std::cerr << "SQLException: " << e.what() << std::endl;
        std::cerr << "SQLState: " << e.getSQLState() << std::endl;
        exit(1);
    }
}

void MasterBase::WaitForClientConnection() {
    while (true) {
        SOCKADDR_IN clientAddr;
        int clientAddrSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (SOCKADDR*)&clientAddr, &clientAddrSize);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed, Err #" << WSAGetLastError() << std::endl;
            continue;
        }

        std::cout << "Client connected!" << std::endl;

        std::thread clientThread([clientSocket, this]() {
            ServerFlowManagement clientManager(clientSocket, this->conn);
            clientManager.ProcessClient();
            });

        clientThread.detach();
    }
}