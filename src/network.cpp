#include "../include/network.hpp"
#include <fstream>
#include <filesystem>
#include <cerrno>
#include <poll.h>

namespace fs = std::filesystem;

// ══════════════════════════════════════════
// Reliable send / recv
// ══════════════════════════════════════════

ssize_t send_all(int fd, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len)
    {
        ssize_t n = ::send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0)
        {
            if (n < 0 && (errno == EINTR))
                continue;
            return -1;
        }
        sent += static_cast<size_t>(n);
    }
    return static_cast<ssize_t>(sent);
}

ssize_t recv_all(int fd, uint8_t *buf, size_t len)
{
    size_t received = 0;
    while (received < len)
    {
        ssize_t n = ::recv(fd, buf + received, len - received, 0);
        if (n <= 0)
        {
            if (n < 0 && (errno == EINTR))
                continue;
            return n == 0 ? 0 : -1; // 0 = peer closed, -1 = error
        }
        received += static_cast<size_t>(n);
    }
    return static_cast<ssize_t>(received);
}

// ══════════════════════════════════════════
// Framed message send / recv
// ══════════════════════════════════════════

bool send_message(int fd, const protocol::Message &msg)
{
    auto wire = protocol::serialize(msg);
    return send_all(fd, wire.data(), wire.size()) == static_cast<ssize_t>(wire.size());
}

std::optional<protocol::Message> recv_message(int fd)
{
    uint8_t header[protocol::HEADER_SIZE];
    if (recv_all(fd, header, protocol::HEADER_SIZE) <= 0)
    {
        return std::nullopt;
    }

    auto parsed = protocol::parse_header(header, protocol::HEADER_SIZE);
    if (!parsed)
        return std::nullopt;

    auto [type, payload_len] = *parsed;

    protocol::Message msg;
    msg.type = type;

    if (payload_len > 0)
    {
        msg.payload.resize(payload_len);
        if (recv_all(fd, msg.payload.data(), payload_len) <= 0)
        {
            return std::nullopt;
        }
    }

    return msg;
}

// ══════════════════════════════════════════
// Receive with timeout (using poll)
// ══════════════════════════════════════════

static std::optional<protocol::Message> recv_message_timeout(int fd, int timeout_sec)
{
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int ret = poll(&pfd, 1, timeout_sec * 1000);
    if (ret <= 0)
        return std::nullopt; // timeout or error
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
        return std::nullopt;

    return recv_message(fd);
}

// ══════════════════════════════════════════
// PeerSession Implementation
// ══════════════════════════════════════════

PeerSession::PeerSession(int socket_fd, bool is_server)
    : socket_fd_(socket_fd), is_server_(is_server)
{
    // Enable TCP keepalive
    int yes = 1;
    setsockopt(socket_fd_, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));

    // Set TCP_NODELAY for low latency chat
    setsockopt(socket_fd_, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

    // Set socket receive timeout (prevents indefinite blocking on recv)
    struct timeval tv;
    tv.tv_sec = 60;
    tv.tv_usec = 0;
    setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // TCP keepalive tuning (detect dead peers faster)
#ifdef __linux__
    int keepidle = 30;  // Start probing after 30s idle
    int keepintvl = 10; // Probe every 10s
    int keepcnt = 3;    // Drop after 3 failed probes
    setsockopt(socket_fd_, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    setsockopt(socket_fd_, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    setsockopt(socket_fd_, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
#endif

    last_heartbeat_recv_.store(now_epoch_sec());
}

PeerSession::~PeerSession()
{
    disconnect();
    heartbeat_running_.store(false);
    if (heartbeat_thread_.joinable())
    {
        heartbeat_thread_.join();
    }
    if (recv_thread_.joinable())
    {
        recv_thread_.join();
    }
    cleanup();
}

int64_t PeerSession::now_epoch_sec() const
{
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

bool PeerSession::perform_handshake()
{
    try
    {
        crypto::KyberKEM kem;

        if (is_server_)
        {
            // Server: Generate keypair, send public key
            auto keypair = kem.generate_keypair();

            protocol::Message pk_msg;
            pk_msg.type = MsgType::HANDSHAKE_PUBKEY;
            pk_msg.payload = keypair.public_key;

            if (!send_message(socket_fd_, pk_msg))
            {
                std::cerr << color::RED << "[!] Failed to send public key" << color::RESET << std::endl;
                return false;
            }

            // Receive ciphertext from client (with timeout)
            auto ct_msg = recv_message_timeout(socket_fd_, HANDSHAKE_TIMEOUT_SEC);
            if (!ct_msg || ct_msg->type != MsgType::HANDSHAKE_CIPHERTEXT)
            {
                std::cerr << color::RED << "[!] Handshake timeout or invalid response" << color::RESET << std::endl;
                return false;
            }

            // Decapsulate to get shared secret
            auto shared_secret = kem.decapsulate(keypair.secret_key, ct_msg->payload);

            // Derive AES-256 session key using session-unique salt
            std::vector<uint8_t> salt(32);
            crypto::random_bytes(salt.data(), salt.size());
            session_key_ = crypto::hkdf_derive_key(shared_secret, salt);

            // Securely erase shared secret
            secure::secure_zero(shared_secret.data(), shared_secret.size());
            secure::secure_zero(keypair.secret_key.data(), keypair.secret_key.size());

            // Send handshake complete with salt
            protocol::Message done_msg;
            done_msg.type = MsgType::HANDSHAKE_COMPLETE;
            done_msg.payload = salt;
            if (!send_message(socket_fd_, done_msg))
                return false;

            // Wait for client's confirmation
            auto ack = recv_message_timeout(socket_fd_, HANDSHAKE_TIMEOUT_SEC);
            if (!ack || ack->type != MsgType::HANDSHAKE_COMPLETE)
                return false;

            // Erase salt from memory
            secure::secure_zero(salt.data(), salt.size());
        }
        else
        {
            // Client: Receive server's public key
            auto pk_msg = recv_message_timeout(socket_fd_, HANDSHAKE_TIMEOUT_SEC);
            if (!pk_msg || pk_msg->type != MsgType::HANDSHAKE_PUBKEY)
            {
                std::cerr << color::RED << "[!] Handshake timeout or invalid public key" << color::RESET << std::endl;
                return false;
            }

            // Encapsulate shared secret
            auto encap = kem.encapsulate(pk_msg->payload);

            // Send ciphertext
            protocol::Message ct_msg;
            ct_msg.type = MsgType::HANDSHAKE_CIPHERTEXT;
            ct_msg.payload = encap.ciphertext;

            if (!send_message(socket_fd_, ct_msg))
            {
                std::cerr << color::RED << "[!] Failed to send ciphertext" << color::RESET << std::endl;
                return false;
            }

            // Wait for server's handshake complete (contains salt)
            auto done = recv_message_timeout(socket_fd_, HANDSHAKE_TIMEOUT_SEC);
            if (!done || done->type != MsgType::HANDSHAKE_COMPLETE)
                return false;

            // Derive AES-256 session key using server's salt
            session_key_ = crypto::hkdf_derive_key(encap.shared_secret, done->payload);

            // Securely erase shared secret
            secure::secure_zero(encap.shared_secret.data(), encap.shared_secret.size());

            // Send our confirmation
            protocol::Message ack_msg;
            ack_msg.type = MsgType::HANDSHAKE_COMPLETE;
            if (!send_message(socket_fd_, ack_msg))
                return false;
        }

        encrypted_.store(true);
        last_heartbeat_recv_.store(now_epoch_sec());
        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << color::RED << "[!] Handshake error: " << e.what() << color::RESET << std::endl;
        return false;
    }
}

void PeerSession::start_receive_loop()
{
    recv_thread_ = std::thread(&PeerSession::receive_loop, this);
}

void PeerSession::start_heartbeat()
{
    heartbeat_running_.store(true);
    heartbeat_thread_ = std::thread(&PeerSession::heartbeat_loop, this);
}

void PeerSession::heartbeat_loop()
{
    while (heartbeat_running_.load() && connected_.load())
    {
        std::this_thread::sleep_for(std::chrono::seconds(HEARTBEAT_INTERVAL_SEC));

        if (!connected_.load() || !heartbeat_running_.load())
            break;

        // Send heartbeat
        {
            std::lock_guard<std::mutex> lock(send_mutex_);
            protocol::Message hb;
            hb.type = MsgType::HEARTBEAT;
            send_message(socket_fd_, hb);
        }

        // Check if peer is alive
        int64_t since = now_epoch_sec() - last_heartbeat_recv_.load();
        if (since > HEARTBEAT_TIMEOUT_SEC)
        {
            std::cerr << color::RED << "[!] Heartbeat timeout — peer unresponsive ("
                      << since << "s)" << color::RESET << std::endl;
            connected_.store(false);
            if (disc_cb_)
                disc_cb_();
            break;
        }
    }
}

void PeerSession::receive_loop()
{
    while (connected_.load())
    {
        auto msg_opt = recv_message(socket_fd_);
        if (!msg_opt)
        {
            if (connected_.load())
            {
                connected_.store(false);
                if (disc_cb_)
                    disc_cb_();
            }
            break;
        }

        auto &msg = *msg_opt;

        // Update heartbeat timestamp on any message
        last_heartbeat_recv_.store(now_epoch_sec());

        // Handle unencrypted control messages
        if (msg.type == MsgType::PING || msg.type == MsgType::HEARTBEAT)
            continue;

        if (msg.type == MsgType::DISCONNECT)
        {
            connected_.store(false);
            if (disc_cb_)
                disc_cb_();
            break;
        }

        // Forward raw handshake messages
        if (msg.type == MsgType::HANDSHAKE_PUBKEY ||
            msg.type == MsgType::HANDSHAKE_CIPHERTEXT ||
            msg.type == MsgType::HANDSHAKE_COMPLETE)
        {
            if (raw_cb_)
                raw_cb_(msg);
            continue;
        }

        // All other messages must be encrypted
        if (!encrypted_.load())
        {
            std::cerr << color::RED << "[!] Received encrypted message before handshake"
                      << color::RESET << std::endl;
            continue;
        }

        auto decrypted = protocol::decrypt_payload(msg, session_key_);
        if (!decrypted)
        {
            int fails = decrypt_fail_count_.fetch_add(1) + 1;
            std::cerr << color::RED << "[!] Decryption failed (tampered or corrupted) ["
                      << fails << "/" << MAX_DECRYPTION_FAILURES << "]"
                      << color::RESET << std::endl;

            // Auto-disconnect on too many failures (possible attack)
            if (fails >= MAX_DECRYPTION_FAILURES)
            {
                std::cerr << color::RED
                          << "[!] Too many decryption failures — disconnecting (possible attack)"
                          << color::RESET << std::endl;
                connected_.store(false);
                if (disc_cb_)
                    disc_cb_();
                break;
            }
            continue;
        }

        // Handle typing indicators (don't need to go through msg_cb_)
        if (msg.type == MsgType::TYPING_START)
        {
            if (typing_cb_)
                typing_cb_(true);
            continue;
        }
        if (msg.type == MsgType::TYPING_STOP)
        {
            if (typing_cb_)
                typing_cb_(false);
            continue;
        }

        // Increment receive counter
        msg_counter_recv_.fetch_add(1);

        // Validate chat message size
        if (msg.type == MsgType::CHAT_MESSAGE && decrypted->size() > MAX_CHAT_MSG_LEN)
        {
            std::cerr << color::RED << "[!] Rejected oversized chat message ("
                      << decrypted->size() << " bytes)" << color::RESET << std::endl;
            continue;
        }

        if (msg_cb_)
        {
            msg_cb_(msg.type, *decrypted);
        }
    }
}

bool PeerSession::send_chat(const std::string &message)
{
    if (message.empty() || message.size() > MAX_CHAT_MSG_LEN)
        return false;
    msg_counter_send_.fetch_add(1);
    return send_encrypted(MsgType::CHAT_MESSAGE, message);
}

bool PeerSession::send_typing(bool is_typing)
{
    if (!encrypted_.load() || !connected_.load())
        return false;
    MsgType type = is_typing ? MsgType::TYPING_START : MsgType::TYPING_STOP;
    return send_encrypted(type, std::vector<uint8_t>{});
}

bool PeerSession::send_file(const std::string &filepath)
{
    if (!encrypted_.load() || !connected_.load())
        return false;

    fs::path path(filepath);
    if (!fs::exists(path) || !fs::is_regular_file(path))
    {
        std::cerr << color::RED << "[!] File not found: " << filepath << color::RESET << std::endl;
        return false;
    }

    // Validate filename length
    std::string filename = path.filename().string();
    if (filename.size() > MAX_FILENAME_LEN)
    {
        std::cerr << color::RED << "[!] Filename too long" << color::RESET << std::endl;
        return false;
    }

    uint64_t file_size = fs::file_size(path);

    // Reject files larger than maximum
    if (file_size > static_cast<uint64_t>(MAX_MSG_SIZE) * 2048)
    {
        std::cerr << color::RED << "[!] File too large" << color::RESET << std::endl;
        return false;
    }

    // Send file header
    auto header_data = protocol::encode_file_header(filename, file_size);
    if (!send_encrypted(MsgType::FILE_HEADER, header_data))
    {
        std::cerr << color::RED << "[!] Failed to send file header" << color::RESET << std::endl;
        return false;
    }

    // Send file chunks
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open())
    {
        std::cerr << color::RED << "[!] Cannot open file: " << filepath << color::RESET << std::endl;
        return false;
    }

    std::vector<uint8_t> chunk(FILE_CHUNK_SIZE);
    uint64_t sent = 0;

    while (sent < file_size && connected_.load())
    {
        size_t to_read = static_cast<size_t>(std::min(static_cast<uint64_t>(FILE_CHUNK_SIZE),
                                                      file_size - sent));
        file.read(reinterpret_cast<char *>(chunk.data()), to_read);
        size_t actually_read = static_cast<size_t>(file.gcount());

        if (actually_read == 0)
            break;

        if (!send_encrypted(MsgType::FILE_CHUNK,
                            std::vector<uint8_t>(chunk.data(), chunk.data() + actually_read)))
        {
            std::cerr << color::RED << "[!] Failed to send file chunk" << color::RESET << std::endl;
            secure::secure_zero(chunk.data(), chunk.size());
            return false;
        }

        sent += actually_read;

        // Print progress
        int pct = static_cast<int>((sent * 100) / file_size);
        std::cout << "\r" << color::DIM << "[>] Sending: " << pct << "% ("
                  << sent << "/" << file_size << " bytes)" << color::RESET << std::flush;
    }

    secure::secure_zero(chunk.data(), chunk.size());

    // Send completion marker
    if (!send_encrypted(MsgType::FILE_COMPLETE, std::vector<uint8_t>{}))
    {
        return false;
    }

    std::cout << "\r" << color::GREEN << "[+] File sent: " << filename
              << " (" << file_size << " bytes)" << color::RESET << std::endl;
    return true;
}

void PeerSession::disconnect()
{
    heartbeat_running_.store(false);
    if (connected_.exchange(false))
    {
        try
        {
            protocol::Message msg;
            msg.type = MsgType::DISCONNECT;
            send_message(socket_fd_, msg);
        }
        catch (...)
        {
        }

        shutdown(socket_fd_, SHUT_RDWR);
        close(socket_fd_);
    }
}

bool PeerSession::send_encrypted(MsgType type, const uint8_t *data, size_t len)
{
    if (!encrypted_.load() || !connected_.load())
        return false;
    std::lock_guard<std::mutex> lock(send_mutex_);
    try
    {
        auto msg = protocol::encrypt_message(type, data, len, session_key_);
        return send_message(socket_fd_, msg);
    }
    catch (const std::exception &e)
    {
        std::cerr << color::RED << "[!] Encrypt/send error: " << e.what() << color::RESET << std::endl;
        return false;
    }
}

bool PeerSession::send_encrypted(MsgType type, const std::string &data)
{
    return send_encrypted(type, reinterpret_cast<const uint8_t *>(data.data()), data.size());
}

bool PeerSession::send_encrypted(MsgType type, const std::vector<uint8_t> &data)
{
    return send_encrypted(type, data.data(), data.size());
}

void PeerSession::cleanup()
{
    // Securely erase session key
    if (!session_key_.empty())
    {
        secure::secure_zero(session_key_.data(), session_key_.size());
        session_key_.clear();
    }
    encrypted_.store(false);
    msg_counter_send_.store(0);
    msg_counter_recv_.store(0);
    decrypt_fail_count_.store(0);
}
