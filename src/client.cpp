#include "../include/client.hpp"
#include <cstring>

std::unique_ptr<PeerSession> Client::connect_to(const std::string &host, uint16_t port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        std::cerr << color::RED << "[!] Socket creation failed" << color::RESET << std::endl;
        return nullptr;
    }

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0)
    {
        std::cerr << color::RED << "[!] Invalid address: " << host << color::RESET << std::endl;
        close(sock);
        return nullptr;
    }

    std::cout << color::CYAN << "[*] Connecting to " << host << ":" << port
              << " ..." << color::RESET << std::endl;

    if (connect(sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        std::cerr << color::RED << "[!] Connection failed: " << strerror(errno)
                  << color::RESET << std::endl;
        close(sock);
        return nullptr;
    }

    std::cout << color::GREEN << "[+] Connected to " << host << ":" << port
              << color::RESET << std::endl;

    return std::make_unique<PeerSession>(sock, false);
}
