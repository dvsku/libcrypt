#pragma once

#include "libcrypt/misc/crypt_result.hpp"

namespace libcrypt {
    class rc4 {
    public:
        rc4();
        rc4(const rc4&) = delete;
        rc4(rc4&&)      = delete;

        rc4& operator=(const rc4&) = delete;
        rc4& operator=(rc4&&)      = delete;

    public:
        /// <summary>
        /// Reset internal state for a new encryption/decryption pass.
        /// Doesn't reset key and iv.
        /// </summary>
        void reset();

        /// <summary>
        /// Set key
        /// </summary>
        void set_key(const char* key, size_t size);

        /// <summary>
        /// Set key
        /// </summary>
        void set_key(const std::string& key);

        /// <summary>
        /// Set iv
        /// </summary>
        void set_iv(uint8_t iv);

        /// <summary>
        /// Get current key
        /// </summary>
        const std::string& get_key() const;

        /// <summary>
        /// Get current iv
        /// </summary>
        uint8_t get_iv() const;

    private:
        bool        m_initialized;
        uint32_t    m_index_A;
        uint32_t    m_index_B;
        uint64_t    m_previous_offset;
        uint8_t     m_box[256];
        std::string m_key;
        uint8_t     m_iv;
    };
}