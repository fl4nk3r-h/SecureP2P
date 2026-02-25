#include "../include/crypto.hpp"
#include <cstring>
#include <stdexcept>

namespace crypto
{

    // ══════════════════════════════════════════
    // ML-KEM-1024 (Kyber) Implementation
    // ══════════════════════════════════════════

    KyberKEM::KyberKEM()
    {
        kem_ = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
        if (!kem_)
        {
            throw std::runtime_error("Failed to initialize ML-KEM-1024. Ensure liboqs supports it.");
        }
    }

    KyberKEM::~KyberKEM()
    {
        if (kem_)
        {
            OQS_KEM_free(kem_);
            kem_ = nullptr;
        }
    }

    KyberKEM::KeyPair KyberKEM::generate_keypair()
    {
        KeyPair kp;
        kp.public_key.resize(kem_->length_public_key);
        kp.secret_key.resize(kem_->length_secret_key);

        // Lock secret key memory
        mlock(kp.secret_key.data(), kp.secret_key.size());

        OQS_STATUS rc = OQS_KEM_keypair(kem_, kp.public_key.data(), kp.secret_key.data());
        if (rc != OQS_SUCCESS)
        {
            secure::secure_zero(kp.secret_key.data(), kp.secret_key.size());
            throw std::runtime_error("ML-KEM-1024 keypair generation failed");
        }
        return kp;
    }

    KyberKEM::EncapResult KyberKEM::encapsulate(const std::vector<uint8_t> &public_key)
    {
        if (public_key.size() != kem_->length_public_key)
        {
            throw std::runtime_error("Invalid public key size for ML-KEM-1024");
        }

        EncapResult result;
        result.ciphertext.resize(kem_->length_ciphertext);
        result.shared_secret.resize(kem_->length_shared_secret);

        mlock(result.shared_secret.data(), result.shared_secret.size());

        OQS_STATUS rc = OQS_KEM_encaps(kem_, result.ciphertext.data(),
                                       result.shared_secret.data(),
                                       public_key.data());
        if (rc != OQS_SUCCESS)
        {
            secure::secure_zero(result.shared_secret.data(), result.shared_secret.size());
            throw std::runtime_error("ML-KEM-1024 encapsulation failed");
        }
        return result;
    }

    secure::SecureVector KyberKEM::decapsulate(const secure::SecureVector &secret_key,
                                               const std::vector<uint8_t> &ciphertext)
    {
        if (secret_key.size() != kem_->length_secret_key)
        {
            throw std::runtime_error("Invalid secret key size for ML-KEM-1024");
        }
        if (ciphertext.size() != kem_->length_ciphertext)
        {
            throw std::runtime_error("Invalid ciphertext size for ML-KEM-1024");
        }

        secure::SecureVector shared_secret(kem_->length_shared_secret);
        mlock(shared_secret.data(), shared_secret.size());

        OQS_STATUS rc = OQS_KEM_decaps(kem_, shared_secret.data(),
                                       ciphertext.data(),
                                       secret_key.data());
        if (rc != OQS_SUCCESS)
        {
            secure::secure_zero(shared_secret.data(), shared_secret.size());
            throw std::runtime_error("ML-KEM-1024 decapsulation failed");
        }
        return shared_secret;
    }

    size_t KyberKEM::public_key_len() const { return kem_->length_public_key; }
    size_t KyberKEM::secret_key_len() const { return kem_->length_secret_key; }
    size_t KyberKEM::ciphertext_len() const { return kem_->length_ciphertext; }
    size_t KyberKEM::shared_secret_len() const { return kem_->length_shared_secret; }

    // ══════════════════════════════════════════
    // HKDF-SHA256 Key Derivation
    // ══════════════════════════════════════════

    secure::SecureVector hkdf_derive_key(const secure::SecureVector &shared_secret,
                                         const std::vector<uint8_t> &salt,
                                         const std::string &info)
    {
        secure::SecureVector derived_key(AES_KEY_SIZE);
        mlock(derived_key.data(), derived_key.size());

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        if (!ctx)
            throw std::runtime_error("HKDF context creation failed");

        size_t out_len = AES_KEY_SIZE;

        if (EVP_PKEY_derive_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_salt(ctx,
                                        salt.empty() ? reinterpret_cast<const unsigned char *>("SecureP2P-Salt-v1") : salt.data(),
                                        salt.empty() ? 17 : static_cast<int>(salt.size())) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_key(ctx,
                                       shared_secret.data(), static_cast<int>(shared_secret.size())) <= 0 ||
            EVP_PKEY_CTX_add1_hkdf_info(ctx,
                                        reinterpret_cast<const unsigned char *>(info.c_str()),
                                        static_cast<int>(info.size())) <= 0 ||
            EVP_PKEY_derive(ctx, derived_key.data(), &out_len) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            secure::secure_zero(derived_key.data(), derived_key.size());
            throw std::runtime_error("HKDF key derivation failed");
        }

        EVP_PKEY_CTX_free(ctx);
        return derived_key;
    }

    // ══════════════════════════════════════════
    // AES-256-GCM Encryption / Decryption
    // ══════════════════════════════════════════

    std::vector<uint8_t> AESGCM::encrypt(const secure::SecureVector &key,
                                         const uint8_t *plaintext, size_t len,
                                         const uint8_t *aad, size_t aad_len)
    {
        if (key.size() != AES_KEY_SIZE)
        {
            throw std::runtime_error("Invalid AES key size");
        }

        // Output: nonce(12) + ciphertext(len) + tag(16)
        std::vector<uint8_t> output(AES_NONCE_SIZE + len + AES_TAG_SIZE);

        // Generate random nonce
        random_bytes(output.data(), AES_NONCE_SIZE);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            throw std::runtime_error("AES-GCM context creation failed");

        int out_len = 0;
        int final_len = 0;

        bool ok = true;
        ok = ok && (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
        ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_NONCE_SIZE, nullptr) == 1);
        ok = ok && (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), output.data()) == 1);

        // Add AAD if provided
        if (aad && aad_len > 0)
        {
            ok = ok && (EVP_EncryptUpdate(ctx, nullptr, &out_len, aad, static_cast<int>(aad_len)) == 1);
        }

        // Encrypt
        ok = ok && (EVP_EncryptUpdate(ctx, output.data() + AES_NONCE_SIZE, &out_len,
                                      plaintext, static_cast<int>(len)) == 1);
        ok = ok && (EVP_EncryptFinal_ex(ctx, output.data() + AES_NONCE_SIZE + out_len, &final_len) == 1);

        // Get tag
        ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE,
                                        output.data() + AES_NONCE_SIZE + len) == 1);

        EVP_CIPHER_CTX_free(ctx);

        if (!ok)
        {
            secure::secure_zero(output.data(), output.size());
            throw std::runtime_error("AES-256-GCM encryption failed");
        }

        return output;
    }

    std::optional<secure::SecureVector> AESGCM::decrypt(
        const secure::SecureVector &key,
        const uint8_t *data, size_t len,
        const uint8_t *aad, size_t aad_len)
    {

        if (key.size() != AES_KEY_SIZE)
            return std::nullopt;
        if (len < AES_NONCE_SIZE + AES_TAG_SIZE)
            return std::nullopt;

        const uint8_t *nonce = data;
        const uint8_t *ciphertext = data + AES_NONCE_SIZE;
        size_t ct_len = len - AES_NONCE_SIZE - AES_TAG_SIZE;
        const uint8_t *tag = data + AES_NONCE_SIZE + ct_len;

        secure::SecureVector plaintext(ct_len);
        mlock(plaintext.data(), plaintext.size());

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            return std::nullopt;

        int out_len = 0;
        int final_len = 0;
        bool ok = true;

        ok = ok && (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
        ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_NONCE_SIZE, nullptr) == 1);
        ok = ok && (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) == 1);

        if (aad && aad_len > 0)
        {
            ok = ok && (EVP_DecryptUpdate(ctx, nullptr, &out_len, aad, static_cast<int>(aad_len)) == 1);
        }

        ok = ok && (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                                      ciphertext, static_cast<int>(ct_len)) == 1);

        // Set expected tag
        ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE,
                                        const_cast<uint8_t *>(tag)) == 1);

        // Verify tag
        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len);
        EVP_CIPHER_CTX_free(ctx);

        if (!ok || ret <= 0)
        {
            secure::secure_zero(plaintext.data(), plaintext.size());
            return std::nullopt;
        }

        plaintext.resize(out_len + final_len);
        return plaintext;
    }

    // Convenience overloads
    std::vector<uint8_t> AESGCM::encrypt(const secure::SecureVector &key,
                                         const std::vector<uint8_t> &plaintext)
    {
        return encrypt(key, plaintext.data(), plaintext.size());
    }

    std::optional<secure::SecureVector> AESGCM::decrypt(
        const secure::SecureVector &key,
        const std::vector<uint8_t> &data)
    {
        return decrypt(key, data.data(), data.size());
    }

    // ══════════════════════════════════════════
    // Cryptographically secure random bytes
    // ══════════════════════════════════════════

    void random_bytes(uint8_t *buf, size_t len)
    {
        if (RAND_bytes(buf, static_cast<int>(len)) != 1)
        {
            throw std::runtime_error("CSPRNG failure: RAND_bytes failed");
        }
    }

} // namespace crypto
