#pragma once

#include "libcrypt/misc/crypt_result.hpp"

#include <filesystem>
#include <vector>
#include <cstdint>

namespace libcrypt {
    class rc4 {
    public:
        using file_path_t = std::filesystem::path;
        using buffer_t    = std::vector<uint8_t>;

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

        // Get current key
        const std::string& get_key() const;

        // Get current iv
        uint8_t get_iv() const;

        // Preforms encryption on the input file and saves the encrypted data to
        // the output file.
        // If output is empty, result will be saved to input.
        crypt_result encrypt_file(const file_path_t& input, const file_path_t& output = "");

        // Preforms encryption on the input file and saves the encrypted data to
        // the out buffer.
        crypt_result encrypt_file(const file_path_t& input, buffer_t& out);

        // Preforms encryption on the buffer.
        // Buffer content and size will be modified.
        crypt_result encrypt_buffer(buffer_t& buffer);

        // Preforms encryption on the data.
        // Data is replaced with encrypted data.
        // Offset is offset from start of stream.
        // Call reset() after you finish encrypting.
        crypt_result encrypt_stream(uint8_t* ptr, size_t size, size_t offset);

        // Preforms decryption on the input file and saves the data to
        // the output file.
        // If output is empty, result will be saved to input.
        crypt_result decrypt_file(const file_path_t& input, const file_path_t& output = "");

        // Preforms decryption on the input file and saves the data to
        // the out buffer.
        crypt_result decrypt_file(const file_path_t& input, buffer_t& out);

        // Preforms decryption on the buffer.
        // Buffer content and size will be modified.
        crypt_result decrypt_buffer(buffer_t& buffer);

        // Preforms decryption on the data.
        // Data is replaced with decrypted data.
        // Offset is offset from start of stream.
        // Call reset() after you finish decrypting.
        crypt_result decrypt_stream(uint8_t* ptr, size_t size, size_t offset);

    private:
        bool        m_initialized;
        uint32_t    m_index_A;
        uint32_t    m_index_B;
        uint64_t    m_previous_offset;
        uint8_t     m_box[256];
        std::string m_key;
        uint8_t     m_iv;

    private:
        void generate_box();

        crypt_result crypt(rc4::buffer_t& buffer);
        crypt_result crypt(uint8_t* ptr, size_t size, size_t offset = 0, bool keep_box = false);
    };
}