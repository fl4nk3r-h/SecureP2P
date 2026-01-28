#include "../include/client.hpp"

void Client::run()
{
#ifdef _WIN32
    WSADATA wsaData;
    int wsaInit = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaInit != 0)
    {
        std::cerr << "WSAStartup failed: " << wsaInit << std::endl;
        return;
    }
#endif

    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    sock = socket(AF_INET, SOCK_STREAM, 0);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    std::string msg = "Hello from client!";
    send(sock, msg.c_str(), msg.size(), 0);

    read(sock, buffer, BUFFER_SIZE);
    std::cout << "Server reply: " << buffer << std::endl;

    close(sock);

#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
}
