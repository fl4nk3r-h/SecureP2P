#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <array>
#include <vector>
#include <memory>
#include <stdexcept>
#include <new>

#include <sys/mman.h> // mlock, munlock
#include <unistd.h>

namespace secure
{

    // ───────────────────────────────────────────
    // Secure erase: guaranteed not optimized away
    // ───────────────────────────────────────────
    inline void secure_zero(void *ptr, size_t len) noexcept
    {
#if defined(__STDC_LIB_EXT1__) || defined(__STDC_WANT_LIB_EXT1__)
        memset_s(ptr, len, 0, len);
#elif defined(__linux__) || defined(__FreeBSD__)
        explicit_bzero(ptr, len);
#else
        volatile unsigned char *p = static_cast<volatile unsigned char *>(ptr);
        while (len--)
            *p++ = 0;
#endif
    }

    // ───────────────────────────────────────────
    // Lock memory to prevent swapping to disk
    // ───────────────────────────────────────────
    inline bool lock_memory(void *ptr, size_t len) noexcept
    {
        return mlock(ptr, len) == 0;
    }

    inline bool unlock_memory(void *ptr, size_t len) noexcept
    {
        return munlock(ptr, len) == 0;
    }

    // ───────────────────────────────────────────
    // Fixed-size secure buffer: mlock'd + zeroed on destroy
    // ───────────────────────────────────────────
    template <size_t N>
    class SecureBuffer
    {
    public:
        SecureBuffer() noexcept
        {
            std::memset(data_.data(), 0, N);
            mlock(data_.data(), N);
        }

        ~SecureBuffer() noexcept
        {
            secure_zero(data_.data(), N);
            munlock(data_.data(), N);
        }

        // Non-copyable to prevent accidental key duplication
        SecureBuffer(const SecureBuffer &) = delete;
        SecureBuffer &operator=(const SecureBuffer &) = delete;

        // Move allowed
        SecureBuffer(SecureBuffer &&other) noexcept
        {
            std::memcpy(data_.data(), other.data_.data(), N);
            mlock(data_.data(), N);
            secure_zero(other.data_.data(), N);
        }

        SecureBuffer &operator=(SecureBuffer &&other) noexcept
        {
            if (this != &other)
            {
                secure_zero(data_.data(), N);
                std::memcpy(data_.data(), other.data_.data(), N);
                secure_zero(other.data_.data(), N);
            }
            return *this;
        }

        uint8_t *data() noexcept { return data_.data(); }
        const uint8_t *data() const noexcept { return data_.data(); }
        constexpr size_t size() const noexcept { return N; }

        uint8_t &operator[](size_t i) noexcept { return data_[i]; }
        const uint8_t &operator[](size_t i) const noexcept { return data_[i]; }

        void clear() noexcept { secure_zero(data_.data(), N); }

    private:
        std::array<uint8_t, N> data_;
    };

    // ───────────────────────────────────────────
    // Secure allocator: zeroes memory on dealloc, uses mlock
    // ───────────────────────────────────────────
    template <typename T>
    class SecureAllocator
    {
    public:
        using value_type = T;

        SecureAllocator() noexcept = default;

        template <typename U>
        SecureAllocator(const SecureAllocator<U> &) noexcept {}

        T *allocate(size_t n)
        {
            if (n > static_cast<size_t>(-1) / sizeof(T))
                throw std::bad_alloc();
            void *raw = std::malloc(n * sizeof(T));
            if (!raw)
                throw std::bad_alloc();
            T *ptr = static_cast<T *>(raw);
            mlock(static_cast<const void *>(ptr), n * sizeof(T));
            return ptr;
        }

        void deallocate(T *ptr, size_t n) noexcept
        {
            if (ptr)
            {
                secure_zero(ptr, n * sizeof(T));
                munlock(ptr, n * sizeof(T));
                std::free(ptr);
            }
        }

        template <typename U>
        bool operator==(const SecureAllocator<U> &) const noexcept { return true; }

        template <typename U>
        bool operator!=(const SecureAllocator<U> &) const noexcept { return false; }
    };

    // ───────────────────────────────────────────
    // Dynamic secure vector: mlock'd + zeroed
    // ───────────────────────────────────────────
    using SecureVector = std::vector<uint8_t, SecureAllocator<uint8_t>>;
    using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;

    // ───────────────────────────────────────────
    // RAII guard to zero a stack buffer on scope exit
    // ───────────────────────────────────────────
    class ScopeZero
    {
    public:
        ScopeZero(void *ptr, size_t len) noexcept : ptr_(ptr), len_(len)
        {
            mlock(ptr_, len_);
        }
        ~ScopeZero() noexcept
        {
            secure_zero(ptr_, len_);
            munlock(ptr_, len_);
        }
        ScopeZero(const ScopeZero &) = delete;
        ScopeZero &operator=(const ScopeZero &) = delete;

    private:
        void *ptr_;
        size_t len_;
    };

} // namespace secure
