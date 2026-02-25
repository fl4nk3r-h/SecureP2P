#pragma once

// ─── Platform ──────────────────────────────
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#endif

#include <iostream>
#include <string>
#include <cstring>
#include <cstdint>
#include <vector>
#include <atomic>
#include <functional>
#include <mutex>
#include <filesystem>
#include <limits>

// ─── Constants ─────────────────────────────
constexpr uint16_t DEFAULT_PORT = 9876;
constexpr size_t BUFFER_SIZE = 65536;
constexpr size_t MAX_MSG_SIZE = 64 * 1024 * 1024; // 64 MB max message
constexpr size_t FILE_CHUNK_SIZE = 32768;         // 32 KB file chunks

// ─── Timing constants ──────────────────────
constexpr int HANDSHAKE_TIMEOUT_SEC = 30;
constexpr int HEARTBEAT_INTERVAL_SEC = 15;
constexpr int HEARTBEAT_TIMEOUT_SEC = 45;
constexpr size_t MAX_CHAT_MSG_LEN = 65000;
constexpr size_t MAX_FILENAME_LEN = 255;
constexpr int MAX_DECRYPTION_FAILURES = 5;

// ─── Message Types ─────────────────────────
enum class MsgType : uint8_t
{
    HANDSHAKE_PUBKEY = 0x01,
    HANDSHAKE_CIPHERTEXT = 0x02,
    HANDSHAKE_COMPLETE = 0x03,

    CHAT_MESSAGE = 0x10,
    TYPING_START = 0x11,
    TYPING_STOP = 0x12,

    FILE_HEADER = 0x20,
    FILE_CHUNK = 0x21,
    FILE_COMPLETE = 0x22,

    HEARTBEAT = 0xFD,
    PING = 0xFE,
    DISCONNECT = 0xFF,
};

// ─── Colors for terminal ───────────────────
namespace color
{
    constexpr const char *RESET = "\033[0m";
    constexpr const char *RED = "\033[1;31m";
    constexpr const char *GREEN = "\033[1;32m";
    constexpr const char *YELLOW = "\033[1;33m";
    constexpr const char *BLUE = "\033[1;34m";
    constexpr const char *MAGENTA = "\033[1;35m";
    constexpr const char *CYAN = "\033[1;36m";
    constexpr const char *WHITE = "\033[1;37m";
    constexpr const char *DIM = "\033[2m";
    constexpr const char *ITALIC = "\033[3m";
    constexpr const char *BOLD = "\033[1m";
}

// ─── Hardening ─────────────────────────────
inline void harden_process()
{
#ifdef __linux__
    // Disable core dumps
    struct rlimit rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);

    // Prevent ptrace attach / memory inspection
    prctl(PR_SET_DUMPABLE, 0);

    // Block SIGPIPE from crashing on broken sockets
    signal(SIGPIPE, SIG_IGN);

    // Disable tracing by any process (requires Linux 3.4+)
    // PR_SET_PTRACER with PR_SET_PTRACER_ANY=0 blocks ptrace
    prctl(PR_SET_PTRACER, 0);

    // Lock all current and future memory to prevent swapping
    // This may fail without CAP_IPC_LOCK; non-fatal
    mlockall(MCL_CURRENT | MCL_FUTURE);
#endif
}

// ─── Secure clear stdin buffer ─────────────
inline void clear_stdin_line()
{
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

// ─── Validate IP address format ────────────
inline bool is_valid_ipv4(const std::string &addr)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, addr.c_str(), &sa.sin_addr) == 1;
}

// ─── Validate port range ───────────────────
inline bool is_valid_port(int port)
{
    return port > 0 && port <= 65535;
}
