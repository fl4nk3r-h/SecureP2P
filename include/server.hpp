#pragma once
#include "common.hpp"
#include "network.hpp"

#include <memory>
#include <string>
#include <functional>

class Server
{
public:
    Server(uint16_t port = DEFAULT_PORT);
    ~Server();

    Server(const Server &) = delete;
    Server &operator=(const Server &) = delete;

    // Start listening and accept one peer connection
    // Returns the connected PeerSession, or nullptr on failure
    std::unique_ptr<PeerSession> accept_peer();

    void stop();
    uint16_t port() const { return port_; }

private:
    int server_fd_ = -1;
    uint16_t port_;
    std::atomic<bool> running_{false};
};
