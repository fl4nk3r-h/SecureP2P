<p align="center">
  <strong>SecureP2P</strong><br>
  <em>Quantum-Safe Encrypted Peer-to-Peer Chat &amp; File Transfer</em>
</p>

<p align="center">
  <img alt="C++17" src="https://img.shields.io/badge/C%2B%2B-17-blue?logo=cplusplus">
  <img alt="CMake" src="https://img.shields.io/badge/CMake-3.10+-064F8C?logo=cmake">
  <img alt="OpenSSL" src="https://img.shields.io/badge/OpenSSL-3.x-721412?logo=openssl">
  <img alt="liboqs" src="https://img.shields.io/badge/liboqs-0.12+-green">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-yellow">
</p>

---

A **hardened**, terminal-based **peer-to-peer** chat and file transfer application using **post-quantum cryptography** (ML-KEM-1024 / Kyber) for key exchange and **AES-256-GCM** for authenticated encryption. Designed to resist both classical and quantum-computer attacks while operating in hostile network environments.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Security Architecture](#security-architecture)
- [Building from Source](#building-from-source)
- [Usage](#usage)
- [Architecture & Design](#architecture--design)
  - [Project Structure](#project-structure)
  - [Class Diagram](#class-diagram)
  - [Component Diagram](#component-diagram)
  - [Sequence Diagrams](#sequence-diagrams)
  - [State Machine Diagrams](#state-machine-diagrams)
  - [Data Flow Diagram](#data-flow-diagram)
- [Wire Protocol](#wire-protocol)
- [Testing](#testing)
- [Threat Model](#threat-model)
- [License](#license)

---

## Quick Start

> **Prerequisites**: GCC 9+ (or Clang 10+), CMake 3.10+, OpenSSL 3.x, liboqs 0.12+

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/SecureP2P.git
cd SecureP2P

# 2. Install liboqs (skip if already installed)
git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
ninja && sudo ninja install && sudo ldconfig
cd ../..

# 3. Build SecureP2P
mkdir -p build && cd build
cmake ..
make -j$(nproc)

# 4. Run the tests
./secureP2P_tests

# 5. Start chatting!
#    Terminal 1 (listener):
./secureP2P listen

#    Terminal 2 (connector):
./secureP2P connect 127.0.0.1
```

Once both terminals display `[+] Quantum-safe session established!`, type messages and press Enter. Use `/file <path>` to send files, `/status` to inspect the connection, and `/quit` to exit securely.

---

## Features

| Category | Feature | Details |
|----------|---------|---------|
| **Encryption** | Post-quantum key exchange | ML-KEM-1024 (FIPS 203 / Kyber) via liboqs |
| **Encryption** | Authenticated encryption | AES-256-GCM with random 96-bit nonces |
| **Encryption** | Key derivation | HKDF-SHA256 with session-unique salt |
| **Encryption** | CSPRNG | OpenSSL `RAND_bytes` for all random data |
| **Chat** | Real-time messaging | Low-latency TCP with `TCP_NODELAY` |
| **Chat** | Typing indicators | Live "peer is typing..." with 2s debounce |
| **Chat** | Timestamps | `[HH:MM:SS]` on all received messages |
| **File Transfer** | Encrypted chunked transfer | 32 KB chunks, each individually encrypted |
| **File Transfer** | Progress bar | Real-time `%` progress on send and receive |
| **File Transfer** | Name collision handling | Automatic rename (`file_1.pdf`, `file_2.pdf`, ...) |
| **Reliability** | Heartbeat | 15s interval, 45s timeout, auto-disconnect on dead peer |
| **Reliability** | TCP keepalive | OS-level dead-peer detection (30s idle, 10s probe, 3 retries) |
| **Reliability** | Tamper detection | Auto-disconnect after 5 consecutive decryption failures |
| **Hardening** | Memory locking | All keys/secrets `mlock()`'d — never swapped to disk |
| **Hardening** | Secure erase | `explicit_bzero()` on all sensitive data at scope exit |
| **Hardening** | Core dumps disabled | `RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0` |
| **Hardening** | Anti-ptrace | Process marked non-dumpable, ptrace blocked |
| **Hardening** | Non-copyable keys | `SecureBuffer` move-only semantics prevent duplication |
| **Hardening** | Zeroing allocator | `SecureAllocator` wipes freed heap memory |
| **Hardening** | Stack protection | `-fstack-protector-strong`, `_FORTIFY_SOURCE=2` |
| **Hardening** | ASLR / RELRO | PIE binary, full RELRO, non-executable stack |

---

## Security Architecture

```mermaid
graph TB
    subgraph "Cryptographic Pipeline"
        A[ML-KEM-1024<br>Key Exchange] -->|shared secret| B[HKDF-SHA256<br>Key Derivation]
        B -->|AES-256 key| C[AES-256-GCM<br>Encrypt / Decrypt]
        D[OpenSSL CSPRNG] -->|nonces & salt| C
        D -->|salt| B
    end

    subgraph "Memory Protection Layer"
        E[SecureBuffer<N>] --- F[mlock on alloc]
        E --- G[explicit_bzero on free]
        E --- H[Non-copyable / move-only]
        I[SecureAllocator] --- J[mlock + zero on dealloc]
        K[ScopeZero RAII] --- L[Automatic wipe on scope exit]
    end

    subgraph "Process Hardening"
        M[RLIMIT_CORE = 0]
        N[PR_SET_DUMPABLE = 0]
        O[PR_SET_PTRACER = 0]
        P["mlockall MCL_CURRENT | MCL_FUTURE"]
        Q[SIGPIPE ignored]
    end

    C --> R[Encrypted Wire Data]
    E --> A
    E --> B
    E --> C
```

---

## Building from Source

### Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| C++ compiler | GCC 9+ / Clang 10+ | C++17 support required |
| CMake | 3.10+ | Build system |
| OpenSSL | 3.x | AES-256-GCM, HKDF-SHA256, CSPRNG |
| liboqs | 0.12+ | ML-KEM-1024 (Kyber) post-quantum KEM |
| pkg-config | any | Locates liboqs |

### Installing liboqs

```bash
git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
ninja && sudo ninja install && sudo ldconfig
```

### Building

```bash
# Standard build
mkdir -p build && cd build
cmake ..
make -j$(nproc)

# Debug build (with AddressSanitizer)
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

### Build Outputs

| Target | Description |
|--------|-------------|
| `build/secureP2P` | Main application binary |
| `build/secureP2P_tests` | Test suite binary |

### Compiler Hardening Flags (applied automatically)

```
-Wall -Wextra -O2
-fstack-protector-strong
-D_FORTIFY_SOURCE=2
-fPIE
-pie -Wl,-z,relro,-z,now,-z,noexecstack
```

---

## Usage

### Start a Listener (Peer A)

```bash
./secureP2P listen [port]
# Aliases: l, server, s
# Default port: 9876
```

### Connect to a Peer (Peer B)

```bash
./secureP2P connect <host> [port]
# Aliases: c, client
# Default port: 9876
```

### Interactive Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `/file <path>` | — | Send a file (absolute or relative path) |
| `/quit` | `/exit`, `/q` | Disconnect and exit securely |
| `/help` | `/h` | Show available commands |
| `/status` | `/s` | Show connection info, message counters, encryption status |

### Example Session

```
# Terminal 1 — Listener
$ ./secureP2P listen 9876
[*] Listening on port 9876 ... waiting for peer
[+] Peer connected from 127.0.0.1:54321
[*] Performing ML-KEM-1024 key exchange...
[+] Quantum-safe session established!
    Cipher: AES-256-GCM | KEM: ML-KEM-1024
    Type /help for commands

you> Hello! This is quantum-safe encrypted chat.
[14:30:05] peer> Hey! Sending you a file now.
[<] Receiving file: document.pdf (1048576 bytes)
[<] Receiving: 100% (1048576/1048576 bytes)
[+] File received: ./received_files/document.pdf (1048576 bytes)
you> Got it. /quit
[*] Disconnecting...
[*] Cleaning up secure session...
[+] Session terminated securely.
```

```
# Terminal 2 — Connector
$ ./secureP2P connect 127.0.0.1 9876
[*] Connecting to 127.0.0.1:9876 ...
[+] Connected to 127.0.0.1:9876
[*] Performing ML-KEM-1024 key exchange...
[+] Quantum-safe session established!
    Cipher: AES-256-GCM | KEM: ML-KEM-1024

[14:30:03] peer> Hello! This is quantum-safe encrypted chat.
you> Hey! Sending you a file now.
you> /file /path/to/document.pdf
[>] Sending: 100% (1048576/1048576 bytes)
[+] File sent: document.pdf (1048576 bytes)
[*] Peer disconnected
```

---

## Architecture & Design

### Project Structure

```
SecureP2P/
├── CMakeLists.txt           # Build configuration with hardening flags
├── LICENSE                  # MIT License
├── README.md                # This file
├── include/
│   ├── common.hpp           # Constants, MsgType enum, color codes, harden_process()
│   ├── secure_memory.hpp    # SecureBuffer<N>, SecureVector, SecureAllocator, ScopeZero
│   ├── crypto.hpp           # KyberKEM, AESGCM, hkdf_derive_key(), random_bytes()
│   ├── protocol.hpp         # Wire format: serialize, parse_header, encrypt/decrypt helpers
│   ├── network.hpp          # PeerSession class, send_all/recv_all, send/recv_message
│   ├── server.hpp           # Server class (TCP listener, accepts one peer)
│   └── client.hpp           # Client class (TCP connector)
├── src/
│   ├── crypto.cpp           # ML-KEM-1024, AES-256-GCM, HKDF-SHA256 implementations
│   ├── network.cpp          # PeerSession: handshake, receive loop, heartbeat, file transfer
│   ├── server.cpp           # Server::accept_peer() — bind, listen, accept
│   ├── client.cpp           # Client::connect_to() — socket, connect
│   └── main.cpp             # Entry point, interactive terminal UI, callback wiring
├── tests/
│   └── test_main.cpp        # Comprehensive test suite (memory, crypto, protocol, integration)
└── build/                   # Build output directory
```

### Class Diagram

```mermaid
classDiagram
    class Server {
        -int server_fd_
        -uint16_t port_
        -atomic~bool~ running_
        +Server(port: uint16_t)
        +~Server()
        +accept_peer() unique_ptr~PeerSession~
        +stop() void
        +port() uint16_t
    }

    class Client {
        +Client()
        +~Client()
        +connect_to(host: string, port: uint16_t) unique_ptr~PeerSession~
    }

    class PeerSession {
        -int socket_fd_
        -bool is_server_
        -atomic~bool~ connected_
        -atomic~bool~ encrypted_
        -SecureVector session_key_
        -mutex send_mutex_
        -thread recv_thread_
        -thread heartbeat_thread_
        -atomic~bool~ heartbeat_running_
        -atomic~uint64_t~ msg_counter_send_
        -atomic~uint64_t~ msg_counter_recv_
        -atomic~int~ decrypt_fail_count_
        -atomic~int64_t~ last_heartbeat_recv_
        -MessageCallback msg_cb_
        -DisconnectCallback disc_cb_
        -RawMessageCallback raw_cb_
        -TypingCallback typing_cb_
        +PeerSession(socket_fd: int, is_server: bool)
        +~PeerSession()
        +perform_handshake() bool
        +start_receive_loop() void
        +start_heartbeat() void
        +send_chat(message: string) bool
        +send_typing(is_typing: bool) bool
        +send_file(filepath: string) bool
        +disconnect() void
        +is_connected() bool
        +is_encrypted() bool
        +messages_sent() uint64_t
        +messages_received() uint64_t
        +decryption_failures() int
        +on_message(cb: MessageCallback) void
        +on_disconnect(cb: DisconnectCallback) void
        +on_raw_message(cb: RawMessageCallback) void
        +on_typing(cb: TypingCallback) void
        -send_encrypted(type: MsgType, data: uint8_t*, len: size_t) bool
        -receive_loop() void
        -heartbeat_loop() void
        -cleanup() void
        -now_epoch_sec() int64_t
    }

    class KyberKEM {
        -OQS_KEM* kem_
        +KyberKEM()
        +~KyberKEM()
        +generate_keypair() KeyPair
        +encapsulate(public_key: vector~uint8_t~) EncapResult
        +decapsulate(secret_key: SecureVector, ciphertext: vector~uint8_t~) SecureVector
        +public_key_len() size_t
        +secret_key_len() size_t
        +ciphertext_len() size_t
        +shared_secret_len() size_t
    }

    class AESGCM {
        +encrypt(key: SecureVector, plaintext: uint8_t*, len: size_t)$ vector~uint8_t~
        +decrypt(key: SecureVector, data: uint8_t*, len: size_t)$ optional~SecureVector~
    }

    class SecureBuffer~N~ {
        -array~uint8_t, N~ data_
        +SecureBuffer()
        +~SecureBuffer()
        +SecureBuffer(SecureBuffer&&)
        +data() uint8_t*
        +size() size_t
        +clear() void
        +operator[](i: size_t) uint8_t&
    }

    class SecureAllocator~T~ {
        +allocate(n: size_t) T*
        +deallocate(ptr: T*, n: size_t) void
    }

    class ScopeZero {
        -void* ptr_
        -size_t len_
        +ScopeZero(ptr: void*, len: size_t)
        +~ScopeZero()
    }

    class Message {
        <<struct>>
        +MsgType type
        +vector~uint8_t~ payload
    }

    class MsgType {
        <<enumeration>>
        HANDSHAKE_PUBKEY = 0x01
        HANDSHAKE_CIPHERTEXT = 0x02
        HANDSHAKE_COMPLETE = 0x03
        CHAT_MESSAGE = 0x10
        TYPING_START = 0x11
        TYPING_STOP = 0x12
        FILE_HEADER = 0x20
        FILE_CHUNK = 0x21
        FILE_COMPLETE = 0x22
        HEARTBEAT = 0xFD
        PING = 0xFE
        DISCONNECT = 0xFF
    }

    Server ..> PeerSession : creates
    Client ..> PeerSession : creates
    PeerSession --> KyberKEM : uses for handshake
    PeerSession --> AESGCM : uses for encryption
    PeerSession --> Message : sends/receives
    PeerSession o-- SecureVector : session_key_
    Message --> MsgType : type
    KyberKEM ..> SecureBuffer~N~ : returns keys in
    KyberKEM ..> SecureVector : returns secrets in
    AESGCM ..> SecureVector : decrypts into
    SecureVector ..> SecureAllocator~uint8_t~ : uses
```

### Component Diagram

```mermaid
graph TB
    subgraph "Application Layer"
        MAIN["main.cpp<br><i>Entry point & Terminal UI</i>"]
    end

    subgraph "Session Layer"
        SERVER["Server<br><i>TCP listener</i>"]
        CLIENT["Client<br><i>TCP connector</i>"]
        PEER["PeerSession<br><i>Encrypted transport<br>+ async I/O</i>"]
    end

    subgraph "Protocol Layer"
        PROTO["protocol.hpp<br><i>Wire format serialization<br>+ encrypt/decrypt helpers</i>"]
    end

    subgraph "Cryptography Layer"
        KYBER["KyberKEM<br><i>ML-KEM-1024 key exchange</i>"]
        AES["AESGCM<br><i>AES-256-GCM</i>"]
        HKDF["hkdf_derive_key<br><i>HKDF-SHA256</i>"]
        RNG["random_bytes<br><i>OpenSSL CSPRNG</i>"]
    end

    subgraph "Secure Memory Layer"
        SBUF["SecureBuffer&lt;N&gt;<br><i>Fixed-size, mlock'd</i>"]
        SVEC["SecureVector<br><i>Dynamic, mlock'd</i>"]
        SALLOC["SecureAllocator<br><i>Zeroing allocator</i>"]
        SZERO["ScopeZero<br><i>RAII wipe guard</i>"]
        SECZ["secure_zero<br><i>explicit_bzero</i>"]
    end

    subgraph "OS / Hardening Layer"
        HARD["harden_process()<br><i>Core dump, ptrace,<br>mlockall, SIGPIPE</i>"]
    end

    subgraph "External Libraries"
        OQS["liboqs 0.12+"]
        OSSL["OpenSSL 3.x"]
    end

    MAIN --> SERVER
    MAIN --> CLIENT
    MAIN --> PEER
    SERVER --> PEER
    CLIENT --> PEER
    PEER --> PROTO
    PEER --> KYBER
    PEER --> AES
    PROTO --> AES
    KYBER --> HKDF
    AES --> RNG
    HKDF --> OSSL
    AES --> OSSL
    RNG --> OSSL
    KYBER --> OQS
    KYBER --> SBUF
    KYBER --> SVEC
    AES --> SVEC
    HKDF --> SVEC
    SVEC --> SALLOC
    SALLOC --> SECZ
    SBUF --> SECZ
    SZERO --> SECZ
    MAIN --> HARD
```

### Sequence Diagrams

#### Connection & Handshake

```mermaid
sequenceDiagram
    participant A as Peer A (Listener)
    participant S as Server
    participant N as Network (TCP)
    participant C as Client
    participant B as Peer B (Connector)

    Note over A: harden_process()
    Note over B: harden_process()

    A->>S: Server(port)
    S->>N: bind() + listen()
    Note over S: Waiting for connection...

    B->>C: Client::connect_to(host, port)
    C->>N: socket() + connect()
    N-->>S: accept()
    S-->>A: PeerSession(fd, is_server=true)
    C-->>B: PeerSession(fd, is_server=false)

    Note over A,B: === ML-KEM-1024 Key Exchange ===

    rect rgb(40, 40, 80)
        A->>A: KyberKEM::generate_keypair()
        Note right of A: (public_key, secret_key)
        A->>N: HANDSHAKE_PUBKEY [public_key]
        N->>B: HANDSHAKE_PUBKEY [public_key]

        B->>B: KyberKEM::encapsulate(public_key)
        Note left of B: (ciphertext, shared_secret)
        B->>N: HANDSHAKE_CIPHERTEXT [ciphertext]
        N->>A: HANDSHAKE_CIPHERTEXT [ciphertext]

        A->>A: KyberKEM::decapsulate(secret_key, ciphertext)
        Note right of A: shared_secret recovered
        A->>A: Generate random salt (32 bytes)
        A->>A: hkdf_derive_key(shared_secret, salt)
        Note right of A: session_key (AES-256)
        A->>A: secure_zero(shared_secret)

        A->>N: HANDSHAKE_COMPLETE [salt]
        N->>B: HANDSHAKE_COMPLETE [salt]

        B->>B: hkdf_derive_key(shared_secret, salt)
        Note left of B: session_key (AES-256)
        B->>B: secure_zero(shared_secret)

        B->>N: HANDSHAKE_COMPLETE []
        N->>A: HANDSHAKE_COMPLETE []
    end

    Note over A,B: ✓ Both peers now share identical AES-256 session key

    A->>A: start_heartbeat() + start_receive_loop()
    B->>B: start_heartbeat() + start_receive_loop()
```

#### Encrypted Chat Message Flow

```mermaid
sequenceDiagram
    participant U as User Input
    participant S as PeerSession (Sender)
    participant AES as AESGCM
    participant P as Protocol
    participant NET as TCP Socket
    participant R as PeerSession (Receiver)
    participant CB as MessageCallback

    U->>S: send_chat("Hello!")
    S->>S: Validate message length ≤ 65000
    S->>S: Acquire send_mutex_
    S->>AES: encrypt(session_key, "Hello!")
    Note over AES: nonce = CSPRNG(12 bytes)
    AES-->>S: nonce(12) || ciphertext || tag(16)
    S->>P: serialize(CHAT_MESSAGE, encrypted_payload)
    P-->>S: [0x10][length:4][encrypted_payload]
    S->>NET: send_all(wire_bytes)
    S->>S: msg_counter_send_++

    NET->>R: recv_all(header 5 bytes)
    R->>P: parse_header()
    P-->>R: (CHAT_MESSAGE, payload_len)
    NET->>R: recv_all(payload)
    R->>R: last_heartbeat_recv_ = now()
    R->>AES: decrypt(session_key, payload)
    AES-->>R: "Hello!" (SecureVector)
    R->>R: msg_counter_recv_++
    R->>CB: on_message(CHAT_MESSAGE, "Hello!")
    CB->>CB: Display with timestamp
```

#### File Transfer Flow

```mermaid
sequenceDiagram
    participant S as Sender
    participant NET as Network
    participant R as Receiver
    participant FS as Filesystem

    S->>S: Validate file exists & size
    S->>S: encode_file_header(filename, size)
    S->>NET: [FILE_HEADER] encrypted(filename + size)
    NET->>R: FILE_HEADER
    R->>R: decode_file_header()
    R->>R: Sanitize filename (strip path)
    R->>FS: Create ./received_files/filename
    R->>R: Print "Receiving file..."

    loop Every 32KB chunk
        S->>S: Read chunk from file
        S->>NET: [FILE_CHUNK] encrypted(chunk)
        NET->>R: FILE_CHUNK
        R->>FS: Write decrypted chunk
        R->>R: Update progress %
    end

    S->>S: secure_zero(chunk_buffer)
    S->>NET: [FILE_COMPLETE] encrypted(empty)
    NET->>R: FILE_COMPLETE
    R->>FS: Close file
    R->>R: Print "File received: ..."
```

### State Machine Diagrams

#### PeerSession Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Created: PeerSession(fd, is_server)

    Created --> Handshaking: perform_handshake()
    Handshaking --> Encrypted: Handshake success
    Handshaking --> Disconnected: Handshake failure / timeout

    Encrypted --> Encrypted: send_chat() / recv message
    Encrypted --> Encrypted: send_file() / recv file
    Encrypted --> Encrypted: Heartbeat exchange
    Encrypted --> Disconnected: /quit command
    Encrypted --> Disconnected: Peer disconnect (DISCONNECT msg)
    Encrypted --> Disconnected: Heartbeat timeout (45s)
    Encrypted --> Disconnected: 5 consecutive decryption failures

    Disconnected --> [*]: ~PeerSession() → secure_zero(session_key)

    state Encrypted {
        [*] --> Idle
        Idle --> SendingChat: send_chat()
        SendingChat --> Idle: sent
        Idle --> SendingFile: send_file()
        SendingFile --> Idle: FILE_COMPLETE sent
        Idle --> ReceivingFile: FILE_HEADER received
        ReceivingFile --> Idle: FILE_COMPLETE received
    }
```

#### Application State Machine

```mermaid
stateDiagram-v2
    [*] --> Init: main(argc, argv)

    Init --> HardenProcess: harden_process()
    HardenProcess --> ParseArgs: Parse CLI arguments

    ParseArgs --> ListenMode: listen / l / server / s
    ParseArgs --> ConnectMode: connect / c / client
    ParseArgs --> Error: Invalid arguments

    ListenMode --> WaitingForPeer: Server accept_peer
    ConnectMode --> Connecting: Client connect_to

    WaitingForPeer --> KeyExchange: Peer connected
    Connecting --> KeyExchange: TCP connected
    WaitingForPeer --> Error: Accept failed
    Connecting --> Error: Connect failed

    KeyExchange --> InteractiveChat: Handshake success
    KeyExchange --> Error: Key exchange failed

    InteractiveChat --> InteractiveChat: Send or receive messages
    InteractiveChat --> InteractiveChat: Send or receive files
    InteractiveChat --> Cleanup: quit or peer disconnect

    Cleanup --> SecureExit: disconnect then secure_zero
    SecureExit --> [*]
    Error --> [*]
```

### Data Flow Diagram

```mermaid
flowchart LR
    subgraph "Plaintext Domain"
        INPUT["User Input<br>(stdin)"]
        OUTPUT["Terminal Output<br>(stdout)"]
        FILE_IN["Local File<br>(read)"]
        FILE_OUT["Received File<br>(write)"]
    end

    subgraph "Encryption Boundary"
        direction TB
        ENC["AES-256-GCM<br>Encrypt"]
        DEC["AES-256-GCM<br>Decrypt"]
        KEY["Session Key<br>(SecureVector)<br>mlock'd"]
    end

    subgraph "Wire Domain"
        WIRE["TCP Socket<br>[type:1][len:4][nonce:12 ‖ ct ‖ tag:16]"]
    end

    INPUT -->|"plaintext"| ENC
    FILE_IN -->|"file chunks"| ENC
    KEY --- ENC
    KEY --- DEC
    ENC -->|"encrypted payload"| WIRE
    WIRE -->|"encrypted payload"| DEC
    DEC -->|"plaintext"| OUTPUT
    DEC -->|"file chunks"| FILE_OUT
```

---

## Wire Protocol

### Frame Format

```
┌──────────┬────────────────────────┬───────────────────────────────────┐
│ Type (1) │ Payload Length (4, BE) │ Payload (variable length)         │
└──────────┴────────────────────────┴───────────────────────────────────┘
```

For encrypted messages, the payload contains:

```
┌───────────────┬──────────────────────────────┬────────────────┐
│ Nonce (12 B)  │ Ciphertext (variable)        │ GCM Tag (16 B) │
└───────────────┴──────────────────────────────┴────────────────┘
```

### Message Types

| Code | Name | Direction | Encrypted | Description |
|------|------|-----------|-----------|-------------|
| `0x01` | `HANDSHAKE_PUBKEY` | Server → Client | No | ML-KEM-1024 public key |
| `0x02` | `HANDSHAKE_CIPHERTEXT` | Client → Server | No | Encapsulated ciphertext |
| `0x03` | `HANDSHAKE_COMPLETE` | Both | No | Acknowledgment (server sends salt) |
| `0x10` | `CHAT_MESSAGE` | Both | Yes | Chat text (≤ 65 KB) |
| `0x11` | `TYPING_START` | Both | Yes | Peer started typing |
| `0x12` | `TYPING_STOP` | Both | Yes | Peer stopped typing |
| `0x20` | `FILE_HEADER` | Sender → Receiver | Yes | `name_len(4) \|\| name \|\| file_size(8)` |
| `0x21` | `FILE_CHUNK` | Sender → Receiver | Yes | File data chunk (≤ 32 KB) |
| `0x22` | `FILE_COMPLETE` | Sender → Receiver | Yes | End-of-file marker |
| `0xFD` | `HEARTBEAT` | Both | No | Keep-alive ping (every 15s) |
| `0xFE` | `PING` | Both | No | One-shot liveness probe |
| `0xFF` | `DISCONNECT` | Both | No | Graceful shutdown |

### File Header Encoding

```
┌──────────────────┬──────────────────────────┬────────────────────────┐
│ name_len (4, BE) │ filename (name_len bytes) │ file_size (8, BE)     │
└──────────────────┴──────────────────────────┴────────────────────────┘
```

---

## Testing

The test suite covers four layers:

```mermaid
graph TD
    subgraph "Test Suite (test_main.cpp)"
        T1["Secure Memory Tests<br>• secure_zero<br>• SecureBuffer init/clear/move<br>• SecureVector allocator<br>• ScopeZero RAII"]
        T2["Cryptography Tests<br>• Kyber keypair generation<br>• Encapsulate / decapsulate<br>• Shared secret match<br>• HKDF key derivation<br>• AES-GCM encrypt/decrypt<br>• Tamper detection<br>• Wrong key rejection<br>• Empty/large payloads"]
        T3["Protocol Tests<br>• Serialize / parse round-trip<br>• Every MsgType<br>• Header rejection (oversized)<br>• File header encode/decode<br>• Encrypt/decrypt message helpers"]
        T4["Integration Tests<br>• Full handshake over loopback<br>• Encrypted chat round-trip<br>• Typing indicator exchange<br>• File transfer end-to-end<br>• Heartbeat exchange<br>• Graceful disconnect"]
    end

    T1 --> T2 --> T3 --> T4
```

### Running Tests

```bash
cd build

# Run directly
./secureP2P_tests

# Or via CTest
ctest --output-on-failure
```

---

## Threat Model

| Threat | Mitigation |
|--------|------------|
| **Quantum computer (CRQC)** | ML-KEM-1024 key exchange is NIST PQC standard (FIPS 203) — resistant to Shor's algorithm |
| **Network eavesdropping** | All messages encrypted with AES-256-GCM; nonces are per-message random |
| **Message tampering** | GCM authentication tag detects any modification; 5 failures = auto-disconnect |
| **Key extraction via swap** | All secrets are `mlock()`'d; `mlockall()` at process start |
| **Key extraction via core dump** | Core dumps disabled (`RLIMIT_CORE=0`); process marked non-dumpable |
| **Key extraction via ptrace** | `PR_SET_DUMPABLE=0` + `PR_SET_PTRACER=0` |
| **Key duplication bugs** | `SecureBuffer` is non-copyable (move-only) |
| **Dangling secrets in memory** | `SecureAllocator` + `ScopeZero` ensure all freed memory is wiped |
| **Buffer overflow** | `-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, bounds-checked message sizes |
| **Dead peer hanging** | TCP keepalive (30s/10s/3) + application heartbeat (15s/45s timeout) |
| **Replay attacks** | Random nonces per message; message counters track send/recv volumes |

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

Copyright (c) 2026 fl4nk3r
