// Adapted from:
//     https://github.com/stbrumme/hash-library

#pragma once

#include <array>
#include <string>
#include <cstdint>

namespace libcrypt {
    class md5 {
    public:
        md5();
        md5(const md5&) = delete;
        md5(md5&&)      = delete;

        md5& operator=(const md5&) = delete;
        md5& operator=(md5&&)      = delete;

    public:
        std::array<uint8_t, 16> compute(const void* data, size_t size);
        std::string to_string(const std::array<uint8_t, 16>& hash);

    private:
        inline static const int BLOCK_SIZE = 64;
        inline static const int HASH_SIZE  = 16;

    private:
        uint64_t m_bytes;
        uint8_t  m_buffer[BLOCK_SIZE];
        size_t   m_buffer_size;
        uint32_t m_hash[HASH_SIZE / 4];

    private:
        void reset();
        void process_block(const void* data);
        void process_buffer();
    };
}
