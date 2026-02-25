#include "../include/server.hpp"
#include <cstring>

Server::Server(uint16_t port) : port_(port) {}

Server::~Server()
{
    stop();
}

std::unique_ptr<PeerSession> Server::accept_peer()
{
    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0)
    {
        std::cerr << color::RED << "[!] Socket creation failed" << color::RESET << std::endl;
        return nullptr;
    }

    int opt = 1;
    setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);

    if (bind(server_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        std::cerr << color::RED << "[!] Bind failed on port " << port_ << color::RESET << std::endl;
        close(server_fd_);
        server_fd_ = -1;
        return nullptr;
    }

    if (listen(server_fd_, 1) < 0)
    {
        std::cerr << color::RED << "[!] Listen failed" << color::RESET << std::endl;
        close(server_fd_);
        server_fd_ = -1;
        return nullptr;
    }

    running_.store(true);
    std::cout << color::CYAN << "[*] Listening on port " << port_
              << " ... waiting for peer" << color::RESET << std::endl;

    struct sockaddr_in peer_addr{};
    socklen_t peer_len = sizeof(peer_addr);
    int peer_fd = accept(server_fd_, reinterpret_cast<sockaddr *>(&peer_addr), &peer_len);

    if (peer_fd < 0)
    {
        if (running_.load())
        {
            std::cerr << color::RED << "[!] Accept failed" << color::RESET << std::endl;
        }
        return nullptr;
    }

    char peer_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, sizeof(peer_ip));
    std::cout << color::GREEN << "[+] Peer connected from " << peer_ip
              << ":" << ntohs(peer_addr.sin_port) << color::RESET << std::endl;

    // Close listening socket - we only support 1 peer (true P2P)
    close(server_fd_);
    server_fd_ = -1;

    return std::make_unique<PeerSession>(peer_fd, true);
}

void Server::stop()
{
    running_.store(false);
    if (server_fd_ >= 0)
    {
        shutdown(server_fd_, SHUT_RDWR);
        close(server_fd_);
        server_fd_ = -1;
    }
}
