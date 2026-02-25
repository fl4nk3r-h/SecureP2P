#pragma once

#include "common.hpp"
#include "crypto.hpp"
#include "secure_memory.hpp"

#include <vector>
#include <optional>
#include <cstring>

namespace protocol
{

    // ─── Wire Format ───────────────────────────
    // [1 byte: type][4 bytes: payload length (network order)][payload...]
    // For encrypted messages, payload = nonce(12) + ciphertext + tag(16)

    constexpr size_t HEADER_SIZE = 5; // type(1) + length(4)

    struct Message
    {
        MsgType type;
        std::vector<uint8_t> payload;
    };

    // Serialize message to wire format
    inline std::vector<uint8_t> serialize(const Message &msg)
    {
        std::vector<uint8_t> wire(HEADER_SIZE + msg.payload.size());
        wire[0] = static_cast<uint8_t>(msg.type);
        uint32_t len = htonl(static_cast<uint32_t>(msg.payload.size()));
        std::memcpy(wire.data() + 1, &len, 4);
        if (!msg.payload.empty())
        {
            std::memcpy(wire.data() + HEADER_SIZE, msg.payload.data(), msg.payload.size());
        }
        return wire;
    }

    // Parse header from buffer, returns (type, payload_length) or nullopt
    inline std::optional<std::pair<MsgType, uint32_t>> parse_header(const uint8_t *buf, size_t avail)
    {
        if (avail < HEADER_SIZE)
            return std::nullopt;
        MsgType type = static_cast<MsgType>(buf[0]);
        uint32_t len;
        std::memcpy(&len, buf + 1, 4);
        len = ntohl(len);
        if (len > MAX_MSG_SIZE)
            return std::nullopt; // Reject oversized
        return std::make_pair(type, len);
    }

    // ─── Encrypted message helpers ─────────────

    // Encrypt and wrap into Message
    inline Message encrypt_message(MsgType type,
                                   const uint8_t *data, size_t len,
                                   const secure::SecureVector &key)
    {
        Message msg;
        msg.type = type;
        msg.payload = crypto::AESGCM::encrypt(key, data, len);
        return msg;
    }

    inline Message encrypt_message(MsgType type,
                                   const std::vector<uint8_t> &data,
                                   const secure::SecureVector &key)
    {
        return encrypt_message(type, data.data(), data.size(), key);
    }

    inline Message encrypt_message(MsgType type,
                                   const std::string &data,
                                   const secure::SecureVector &key)
    {
        return encrypt_message(type,
                               reinterpret_cast<const uint8_t *>(data.data()),
                               data.size(), key);
    }

    // Decrypt payload from Message
    inline std::optional<secure::SecureVector> decrypt_payload(const Message &msg,
                                                               const secure::SecureVector &key)
    {
        return crypto::AESGCM::decrypt(key, msg.payload);
    }

    // ─── File transfer header encoding ────────
    // Format: filename_len(4) + filename + file_size(8)
    inline std::vector<uint8_t> encode_file_header(const std::string &filename, uint64_t file_size)
    {
        std::vector<uint8_t> buf(4 + filename.size() + 8);
        uint32_t name_len = htonl(static_cast<uint32_t>(filename.size()));
        std::memcpy(buf.data(), &name_len, 4);
        std::memcpy(buf.data() + 4, filename.data(), filename.size());
        // Store file size in network byte order (big endian)
        for (int i = 7; i >= 0; --i)
        {
            buf[4 + filename.size() + (7 - i)] = (file_size >> (i * 8)) & 0xFF;
        }
        return buf;
    }

    inline bool decode_file_header(const uint8_t *data, size_t len,
                                   std::string &filename, uint64_t &file_size)
    {
        if (len < 12)
            return false;
        uint32_t name_len;
        std::memcpy(&name_len, data, 4);
        name_len = ntohl(name_len);
        if (4 + name_len + 8 > len)
            return false;
        if (name_len > 4096)
            return false; // Sanity check
        filename.assign(reinterpret_cast<const char *>(data + 4), name_len);
        file_size = 0;
        for (int i = 0; i < 8; ++i)
        {
            file_size = (file_size << 8) | data[4 + name_len + i];
        }
        return true;
    }

} // namespace protocol
