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
        // Reset internal state for a new encryption/decryption pass.
        // Doesn't reset key and iv.
        void reset();

        // Set key
        void set_key(const char* key, size_t size);

        // Set key
        void set_key(const std::string& key);

        // Set iv
        void set_iv(uint8_t iv);

        // Set key and iv via key file
        crypt_result set_via_key_file(const file_path_t& file);

        // Get current key
        const std::string& get_key() const;

        // Get current iv
        uint8_t get_iv() const;

        // Check if a file is a rc4 key file
        bool is_key_file(const file_path_t& file);

        // Create a key file
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