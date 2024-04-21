#pragma once

#include "libcrypt/misc/crypt_result.hpp"

#include <filesystem>

namespace libcrypt {
    class rc4 {
    public:
        using file_path_t = std::filesystem::path;

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
        /// Set key and iv via key file
        /// </summary>
        crypt_result set_via_key_file(const file_path_t& file);

        /// <summary>
        /// Get current key
        /// </summary>
        const std::string& get_key() const;

        /// <summary>
        /// Get current iv
        /// </summary>
        uint8_t get_iv() const;

        /// <summary>
        /// Check if a file is a rc4 key file
        /// </summary>
        bool is_key_file(const file_path_t& file);

        /// <summary>
        /// Create a key file
        /// </summary>
        crypt_result create_key_file(const file_path_t& file, const std::string& key, uint8_t iv);

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