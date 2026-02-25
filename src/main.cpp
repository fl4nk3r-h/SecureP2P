// ═══════════════════════════════════════════════════════════════
// SecureP2P - Quantum-Safe Encrypted Peer-to-Peer Chat
// ML-KEM-1024 (Kyber) Key Exchange + AES-256-GCM Encryption
// ═══════════════════════════════════════════════════════════════

#include "../include/server.hpp"
#include "../include/client.hpp"
#include "../include/secure_memory.hpp"

#include <iostream>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <cstdlib>
#include <termios.h>

namespace fs = std::filesystem;

// ─── Globals ──────────────────────────────
static std::atomic<bool> g_running{true};
static std::mutex g_output_mutex;
static std::string g_download_dir = "./received_files";

// ─── Live chat: typing indicator state ────
static std::atomic<bool> g_peer_typing{false};
static std::atomic<bool> g_local_typing_sent{false};
static std::chrono::steady_clock::time_point g_last_keystroke;
static constexpr int TYPING_DEBOUNCE_MS = 2000; // Send TYPING_STOP after 2s idle

// ─── File receive state ───────────────────
static std::mutex g_file_mutex;
static bool g_receiving_file = false;
static std::string g_recv_filename;
static uint64_t g_recv_filesize = 0;
static uint64_t g_recv_bytes = 0;
static std::ofstream g_recv_stream;

// ─── Thread-safe terminal output ──────────
static void print_line(const std::string &msg)
{
    std::lock_guard<std::mutex> lock(g_output_mutex);
    // Clear current input line, print message, restore prompt
    std::cout << "\r\033[K" << msg << std::endl;
    if (g_running.load())
    {
        // Show typing indicator above prompt if peer is typing
        if (g_peer_typing.load())
        {
            std::cout << color::DIM << color::ITALIC
                      << "  peer is typing..." << color::RESET << std::endl;
        }
        std::cout << color::BOLD << color::BLUE << "you> " << color::RESET << std::flush;
    }
}

// ─── Banner ───────────────────────────────
static void print_banner()
{
    std::cout << color::CYAN << R"(
  ╔═══════════════════════════════════════════════════╗
  ║         SecureP2P - Quantum-Safe Chat             ║
  ║   ML-KEM-1024 (Kyber) + AES-256-GCM Encryption    ║
  ╠═══════════════════════════════════════════════════╣
  ║  Commands:                                        ║
  ║    /file <path>   - Send a file                   ║
  ║    /quit           - Disconnect and exit          ║
  ║    /help           - Show this help               ║
  ║    /status         - Show connection status       ║
  ║                                                   ║
  ║  Live Chat: Typing indicators + heartbeat active  ║
  ╚═══════════════════════════════════════════════════╝
)" << color::RESET
              << std::endl;
}

static void print_help()
{
    print_line(std::string(color::CYAN) +
               "Commands:\n"
               "  /file <path>   - Send a file (absolute or relative path)\n"
               "  /quit          - Disconnect and exit securely\n"
               "  /help          - Show this help\n"
               "  /status        - Show connection info" +
               color::RESET);
}

// ─── Message handler callback ─────────────
static void on_message(MsgType type, const secure::SecureVector &data)
{
    switch (type)
    {
    case MsgType::CHAT_MESSAGE:
    {
        std::string text(data.begin(), data.end());
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        char tstamp[16];
        std::strftime(tstamp, sizeof(tstamp), "%H:%M:%S", std::localtime(&time));

        print_line(std::string(color::DIM) + "[" + tstamp + "] " +
                   color::GREEN + "peer> " + color::RESET + text);
        break;
    }

    case MsgType::FILE_HEADER:
    {
        std::lock_guard<std::mutex> lock(g_file_mutex);
        std::string filename;
        uint64_t fsize;
        if (!protocol::decode_file_header(data.data(), data.size(), filename, fsize))
        {
            print_line(std::string(color::RED) + "[!] Invalid file header" + color::RESET);
            break;
        }

        // Sanitize filename - strip path components
        fs::path safe_name = fs::path(filename).filename();
        if (safe_name.empty() || safe_name.string()[0] == '.')
        {
            safe_name = "received_file";
        }

        // Create download directory
        fs::create_directories(g_download_dir);

        // Handle name collisions
        fs::path dest = fs::path(g_download_dir) / safe_name;
        int counter = 1;
        while (fs::exists(dest))
        {
            std::string stem = safe_name.stem().string();
            std::string ext = safe_name.extension().string();
            dest = fs::path(g_download_dir) / (stem + "_" + std::to_string(counter++) + ext);
        }

        g_recv_filename = dest.string();
        g_recv_filesize = fsize;
        g_recv_bytes = 0;
        g_recv_stream.open(g_recv_filename, std::ios::binary | std::ios::trunc);

        if (!g_recv_stream.is_open())
        {
            print_line(std::string(color::RED) + "[!] Cannot create file: " +
                       g_recv_filename + color::RESET);
            break;
        }

        g_receiving_file = true;
        print_line(std::string(color::YELLOW) + "[<] Receiving file: " +
                   safe_name.string() + " (" + std::to_string(fsize) + " bytes)" + color::RESET);
        break;
    }

    case MsgType::FILE_CHUNK:
    {
        std::lock_guard<std::mutex> lock(g_file_mutex);
        if (!g_receiving_file || !g_recv_stream.is_open())
            break;

        g_recv_stream.write(reinterpret_cast<const char *>(data.data()), data.size());
        g_recv_bytes += data.size();

        int pct = g_recv_filesize > 0
                      ? static_cast<int>((g_recv_bytes * 100) / g_recv_filesize)
                      : 100;

        {
            std::lock_guard<std::mutex> olock(g_output_mutex);
            std::cout << "\r\033[K" << color::DIM << "[<] Receiving: " << pct << "% ("
                      << g_recv_bytes << "/" << g_recv_filesize << " bytes)"
                      << color::RESET << std::flush;
        }
        break;
    }

    case MsgType::FILE_COMPLETE:
    {
        std::lock_guard<std::mutex> lock(g_file_mutex);
        if (g_recv_stream.is_open())
        {
            g_recv_stream.close();
        }
        g_receiving_file = false;
        print_line(std::string(color::GREEN) + "[+] File received: " +
                   g_recv_filename + " (" + std::to_string(g_recv_bytes) + " bytes)" + color::RESET);
        break;
    }

    default:
        break;
    }
}

// ─── Input loop ───────────────────────────
static void input_loop(PeerSession &session)
{
    std::string line;

    std::cout << color::BOLD << color::BLUE << "you> " << color::RESET << std::flush;

    while (g_running.load() && session.is_connected())
    {
        if (!std::getline(std::cin, line))
        {
            break; // EOF
        }

        if (line.empty())
        {
            std::cout << color::BOLD << color::BLUE << "you> " << color::RESET << std::flush;
            continue;
        }

        // Handle commands
        if (line[0] == '/')
        {
            if (line == "/quit" || line == "/exit" || line == "/q")
            {
                print_line(std::string(color::YELLOW) + "[*] Disconnecting..." + color::RESET);
                g_running.store(false);
                session.disconnect();
                break;
            }
            else if (line == "/help" || line == "/h")
            {
                print_help();
                continue;
            }
            else if (line == "/status" || line == "/s")
            {
                std::string status = std::string(color::CYAN) +
                                     "[i] Connected: " + (session.is_connected() ? "yes" : "no") + "\n" +
                                     "    Encrypted: " + (session.is_encrypted() ? "AES-256-GCM (ML-KEM-1024)" : "no") + "\n" +
                                     "    Messages sent: " + std::to_string(session.messages_sent()) + "\n" +
                                     "    Messages received: " + std::to_string(session.messages_received()) + "\n" +
                                     "    Decryption failures: " + std::to_string(session.decryption_failures()) + "\n" +
                                     "    Peer typing: " + (g_peer_typing.load() ? "yes" : "no") + "\n" +
                                     "    Download dir: " + g_download_dir +
                                     color::RESET;
                print_line(status);
                continue;
            }
            else if (line.substr(0, 5) == "/file")
            {
                std::string path = line.substr(5);
                // Trim leading spaces
                size_t start = path.find_first_not_of(' ');
                if (start == std::string::npos || path.empty())
                {
                    print_line(std::string(color::RED) + "[!] Usage: /file <path>" + color::RESET);
                    std::cout << color::BOLD << color::BLUE << "you> " << color::RESET << std::flush;
                    continue;
                }
                path = path.substr(start);
                // Trim trailing spaces
                size_t end = path.find_last_not_of(' ');
                if (end != std::string::npos)
                    path = path.substr(0, end + 1);

                // Launch file send in background thread
                std::thread([&session, path]()
                            { session.send_file(path); })
                    .detach();

                std::cout << color::BOLD << color::BLUE << "you> " << color::RESET << std::flush;
                continue;
            }
            else
            {
                print_line(std::string(color::RED) + "[!] Unknown command. Type /help" + color::RESET);
                std::cout << color::BOLD << color::BLUE << "you> " << color::RESET << std::flush;
                continue;
            }
        }

        // Regular chat message
        session.send_typing(false); // Stop typing indicator before send
        g_local_typing_sent.store(false);

        if (!session.send_chat(line))
        {
            print_line(std::string(color::RED) + "[!] Failed to send message" + color::RESET);
        }

        std::cout << color::BOLD << color::BLUE << "you> " << color::RESET << std::flush;
    }
}

// ─── Usage ────────────────────────────────
static void print_usage(const char *prog)
{
    std::cerr << "Usage:" << std::endl;
    std::cerr << "  " << prog << " listen [port]          - Wait for incoming connection" << std::endl;
    std::cerr << "  " << prog << " connect <host> [port]  - Connect to a peer" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Default port: " << DEFAULT_PORT << std::endl;
}

// ─── Main ─────────────────────────────────
int main(int argc, char *argv[])
{
    // ─── Harden the process ───────────────
    harden_process();

    if (argc < 2)
    {
        print_usage(argv[0]);
        return 1;
    }

    std::string mode = argv[1];
    std::unique_ptr<PeerSession> session;

    print_banner();

    if (mode == "listen" || mode == "l" || mode == "server" || mode == "s")
    {
        // ─── Server mode ──────────────────
        uint16_t port = DEFAULT_PORT;
        if (argc >= 3)
        {
            port = static_cast<uint16_t>(std::atoi(argv[2]));
        }

        Server server(port);
        session = server.accept_peer();
        if (!session)
        {
            std::cerr << color::RED << "[!] Failed to accept connection" << color::RESET << std::endl;
            return 1;
        }
    }
    else if (mode == "connect" || mode == "c" || mode == "client")
    {
        // ─── Client mode ──────────────────
        if (argc < 3)
        {
            std::cerr << color::RED << "[!] Missing host address" << color::RESET << std::endl;
            print_usage(argv[0]);
            return 1;
        }
        std::string host = argv[2];
        uint16_t port = DEFAULT_PORT;
        if (argc >= 4)
        {
            port = static_cast<uint16_t>(std::atoi(argv[3]));
        }

        Client client;
        session = client.connect_to(host, port);
        if (!session)
        {
            std::cerr << color::RED << "[!] Failed to connect" << color::RESET << std::endl;
            return 1;
        }
    }
    else
    {
        print_usage(argv[0]);
        return 1;
    }

    // ─── Quantum-safe key exchange ────────
    std::cout << color::YELLOW << "[*] Performing ML-KEM-1024 key exchange..." << color::RESET << std::endl;

    if (!session->perform_handshake())
    {
        std::cerr << color::RED << "[!] Key exchange failed! Aborting." << color::RESET << std::endl;
        return 1;
    }

    std::cout << color::GREEN << "[+] Quantum-safe session established!" << std::endl;
    std::cout << "    Cipher: AES-256-GCM | KEM: ML-KEM-1024" << color::RESET << std::endl;
    std::cout << color::DIM << "    Type /help for commands" << color::RESET << std::endl;
    std::cout << std::endl;

    // ─── Set up callbacks ─────────────────
    session->on_message(on_message);
    session->on_disconnect([]()
                           {
        print_line(std::string(color::YELLOW) + "[*] Peer disconnected" + color::RESET);
        g_running.store(false); });

    // Typing indicator callback
    session->on_typing([](bool is_typing)
                       {
        g_peer_typing.store(is_typing);
        std::lock_guard<std::mutex> lock(g_output_mutex);
        if (is_typing)
        {
            std::cout << "\r\033[K" << color::DIM << color::ITALIC
                      << "  peer is typing..." << color::RESET << std::endl;
            std::cout << color::BOLD << color::BLUE << "you> " << color::RESET << std::flush;
        }
        else
        {
            // Clear the typing line
            std::cout << "\r\033[K"
                      << color::BOLD << color::BLUE << "you> " << color::RESET << std::flush;
        } });

    // ─── Start heartbeat & async receive ──
    session->start_heartbeat();
    session->start_receive_loop();

    // ─── Interactive input loop ───────────
    input_loop(*session);

    // ─── Cleanup ──────────────────────────
    std::cout << std::endl;
    std::cout << color::YELLOW << "[*] Cleaning up secure session..." << color::RESET << std::endl;
    session->disconnect();
    session.reset(); // Triggers secure memory wipe

    // Close any open file
    {
        std::lock_guard<std::mutex> lock(g_file_mutex);
        if (g_recv_stream.is_open())
            g_recv_stream.close();
    }

    std::cout << color::GREEN << "[+] Session terminated securely." << color::RESET << std::endl;
    return 0;
}
