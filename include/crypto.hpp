#pragma once

#include "common.hpp"
#include "secure_memory.hpp"

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <optional>
#include <tuple>
#include <stdexcept>

namespace crypto
{

    // ─── Constants ─────────────────────────────
    constexpr size_t AES_KEY_SIZE = 32;   // 256 bits
    constexpr size_t AES_NONCE_SIZE = 12; // 96 bits for GCM
    constexpr size_t AES_TAG_SIZE = 16;   // 128 bits

    // ─── ML-KEM-1024 (Kyber) Key Exchange ──────
    class KyberKEM
    {
    public:
        KyberKEM();
        ~KyberKEM();
        KyberKEM(const KyberKEM &) = delete;
        KyberKEM &operator=(const KyberKEM &) = delete;

        // Server side: generate keypair
        struct KeyPair
        {
            std::vector<uint8_t> public_key;
            secure::SecureVector secret_key;
        };
        KeyPair generate_keypair();

        // Client side: encapsulate (creates shared secret from public key)
        struct EncapResult
        {
            std::vector<uint8_t> ciphertext;
            secure::SecureVector shared_secret;
        };
        EncapResult encapsulate(const std::vector<uint8_t> &public_key);

        // Server side: decapsulate (recovers shared secret)
        secure::SecureVector decapsulate(const secure::SecureVector &secret_key,
                                         const std::vector<uint8_t> &ciphertext);

        size_t public_key_len() const;
        size_t secret_key_len() const;
        size_t ciphertext_len() const;
        size_t shared_secret_len() const;

    private:
        OQS_KEM *kem_;
    };

    // ─── HKDF Key Derivation ──────────────────
    // Derives AES-256 key from shared secret
    secure::SecureVector hkdf_derive_key(const secure::SecureVector &shared_secret,
                                         const std::vector<uint8_t> &salt = {},
                                         const std::string &info = "SecureP2P-AES256GCM");

    // ─── AES-256-GCM Encryption ───────────────
    class AESGCM
    {
    public:
        // Encrypt plaintext with optional AAD
        // Returns: nonce (12) || ciphertext || tag (16)
        static std::vector<uint8_t> encrypt(const secure::SecureVector &key,
                                            const uint8_t *plaintext, size_t len,
                                            const uint8_t *aad = nullptr, size_t aad_len = 0);

        // Decrypt: input = nonce (12) || ciphertext || tag (16)
        // Returns plaintext, or empty on auth failure
        static std::optional<secure::SecureVector> decrypt(
            const secure::SecureVector &key,
            const uint8_t *data, size_t len,
            const uint8_t *aad = nullptr, size_t aad_len = 0);

        // Convenience overloads
        static std::vector<uint8_t> encrypt(const secure::SecureVector &key,
                                            const std::vector<uint8_t> &plaintext);
        static std::optional<secure::SecureVector> decrypt(
            const secure::SecureVector &key,
            const std::vector<uint8_t> &data);
    };

    // ─── Secure random bytes ──────────────────
    void random_bytes(uint8_t *buf, size_t len);

} // namespace crypto
