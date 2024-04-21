#include "libcrypt/rc4/rc4.hpp"

#include <sstream>

using namespace libcrypt;

///////////////////////////////////////////////////////////////////////////////
// INTERNAL

static std::string internal_parse_key(const char* key, size_t size);
static std::string internal_hex_string_to_string(const std::string& hex_string);

///////////////////////////////////////////////////////////////////////////////
// PUBLIC

rc4::rc4() {
    reset();

    m_key = "";
    m_iv  = 0U;
}

void rc4::reset() {
    m_initialized     = false;
    m_index_A         = 0U;
    m_index_B         = 0U;
    m_previous_offset = 0U;

    std::memset(m_box, 0, sizeof(m_box));
}

void rc4::set_key(const char* key, size_t size) {
    if (!key) return;

    m_key = internal_parse_key(key, size);
}

void rc4::set_key(const std::string& key) {
    set_key(key.data(), key.size());
}

void rc4::set_iv(uint8_t iv) {
    m_iv = iv;
}

const std::string& rc4::get_key() const {
    return m_key;
}

uint8_t rc4::get_iv() const {
    return m_iv;
}

///////////////////////////////////////////////////////////////////////////////
// INTERNAL

std::string internal_parse_key(const char* key, size_t size) {
    if (size >= 2 && key[0] == '0' && (key[1] == 'x' || key[1] == 'X'))
        return internal_hex_string_to_string(std::string(key, key + size));

    return std::string(key, key + size);
}

std::string internal_hex_string_to_string(const std::string& hex_string) {
    std::string hex_data = hex_string.substr(2);

    if (hex_data.length() % 2 != 0)
        hex_data = '0' + hex_data;

    std::stringstream ss;
    for (size_t i = 0; i < hex_data.length(); i += 2)
        ss << static_cast<char>(std::stoi(hex_data.substr(i, 2), nullptr, 16));

    return ss.str();
}
