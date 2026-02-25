#pragma once
#include "common.hpp"
#include "network.hpp"

#include <memory>
#include <string>

class Client
{
public:
    Client() = default;
    ~Client() = default;

    Client(const Client &) = delete;
    Client &operator=(const Client &) = delete;

    // Connect to a peer and return the session
    std::unique_ptr<PeerSession> connect_to(const std::string &host, uint16_t port = DEFAULT_PORT);
};
