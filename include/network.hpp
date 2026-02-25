#pragma once

#include "common.hpp"
#include "crypto.hpp"
#include "protocol.hpp"
#include "secure_memory.hpp"

#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <atomic>
#include <optional>
#include <chrono>

// ─── Reliable send/recv helpers ────────────
// Blocks until all bytes sent/received or error
ssize_t send_all(int fd, const uint8_t *buf, size_t len);
ssize_t recv_all(int fd, uint8_t *buf, size_t len);

// ─── Send a framed protocol message ────────
bool send_message(int fd, const protocol::Message &msg);

// ─── Receive a framed protocol message ─────
// Blocks until a full message is read, or returns nullopt on error/disconnect
std::optional<protocol::Message> recv_message(int fd);

// ═══════════════════════════════════════════
// PeerSession: manages a single encrypted P2P connection
// ═══════════════════════════════════════════
class PeerSession
{
public:
    using MessageCallback = std::function<void(MsgType, const secure::SecureVector &)>;
    using DisconnectCallback = std::function<void()>;
    using RawMessageCallback = std::function<void(const protocol::Message &)>;
    using TypingCallback = std::function<void(bool)>;

    PeerSession(int socket_fd, bool is_server);
    ~PeerSession();

    PeerSession(const PeerSession &) = delete;
    PeerSession &operator=(const PeerSession &) = delete;

    // Perform the Kyber key exchange (blocking)
    bool perform_handshake();

    // Start async receive loop (calls callbacks)
    void start_receive_loop();

    // Start heartbeat thread
    void start_heartbeat();

    // Send encrypted chat message
    bool send_chat(const std::string &message);

    // Send typing indicator
    bool send_typing(bool is_typing);

    // Send file
    bool send_file(const std::string &filepath);

    // Send disconnect and close
    void disconnect();

    // Check connection status
    bool is_connected() const { return connected_.load(); }
    bool is_encrypted() const { return encrypted_.load(); }

    // Get session info
    uint64_t messages_sent() const { return msg_counter_send_.load(); }
    uint64_t messages_received() const { return msg_counter_recv_.load(); }
    int decryption_failures() const { return decrypt_fail_count_.load(); }

    // Register callbacks
    void on_message(MessageCallback cb) { msg_cb_ = std::move(cb); }
    void on_disconnect(DisconnectCallback cb) { disc_cb_ = std::move(cb); }
    void on_raw_message(RawMessageCallback cb) { raw_cb_ = std::move(cb); }
    void on_typing(TypingCallback cb) { typing_cb_ = std::move(cb); }

private:
    int socket_fd_;
    bool is_server_;
    std::atomic<bool> connected_{true};
    std::atomic<bool> encrypted_{false};

    secure::SecureVector session_key_;
    std::mutex send_mutex_;
    std::thread recv_thread_;
    std::thread heartbeat_thread_;
    std::atomic<bool> heartbeat_running_{false};

    // Message counters for anti-replay / stats
    std::atomic<uint64_t> msg_counter_send_{0};
    std::atomic<uint64_t> msg_counter_recv_{0};

    // Decryption failure counter (auto-disconnect on threshold)
    std::atomic<int> decrypt_fail_count_{0};

    // Last heartbeat timestamp
    std::atomic<int64_t> last_heartbeat_recv_{0};

    MessageCallback msg_cb_;
    DisconnectCallback disc_cb_;
    RawMessageCallback raw_cb_;
    TypingCallback typing_cb_;

    bool send_encrypted(MsgType type, const uint8_t *data, size_t len);
    bool send_encrypted(MsgType type, const std::string &data);
    bool send_encrypted(MsgType type, const std::vector<uint8_t> &data);
    void receive_loop();
    void heartbeat_loop();
    void cleanup();
    int64_t now_epoch_sec() const;
};
