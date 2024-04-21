#include "libcrypt/rc4/rc4.hpp"

#include <fstream>
#include <sstream>

using namespace libcrypt;

///////////////////////////////////////////////////////////////////////////////
// INTERNAL

static const uint32_t MAGIC = 0x20464B44;

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

crypt_result rc4::set_via_key_file(const file_path_t& file) {
    crypt_result result;

    if (!is_key_file(file)) {
        result.message = "Not a key file.";
        return result;
    }

    std::ifstream fin(file, std::ios::binary);
    if (!fin.is_open()) {
        result.message = "Failed to open key file.";
        return result;
    }

    fin.seekg(4, std::ios::beg);

    std::string key      = "";
    uint32_t    key_size = 0U;
    uint8_t     iv       = 0U;
    
    fin.read((char*)&iv,       sizeof(iv));
    fin.read((char*)&key_size, sizeof(key_size));

    key.resize(key_size);
    fin.read(key.data(), key_size);

    set_iv(iv);
    set_key(key);

    result.success = true;
    return result;
}

const std::string& rc4::get_key() const {
    return m_key;
}

uint8_t rc4::get_iv() const {
    return m_iv;
}

bool rc4::is_key_file(const file_path_t& file) {
    if (!std::filesystem::exists(file))
        return false;

    if (!file.has_extension() || file.extension() != ".dkf")
        return false;

    std::ifstream fin(file, std::ios::binary);
    if (!fin.is_open())
        return false;

    uint32_t magic = 0U;
    fin.read((char*)&magic, sizeof(magic));

    return magic == MAGIC;
}

crypt_result rc4::create_key_file(const file_path_t& file, const std::string& key, uint8_t iv) {
    crypt_result result;

    if (!file.has_extension() || file.extension() != ".dkf") {
        result.message = "Extension must be `dkf`.";
        return result;
    }

    std::string l_key      = internal_parse_key(key.data(), key.size());
    uint32_t    l_key_size = (uint32_t)l_key.size();


    std::ofstream fout(file, std::ios::binary);
    if (!fout.is_open()) {
        result.message = "Failed to open file.";
        return result;
    }

    fout.write((char*)&MAGIC,       sizeof(MAGIC));
    fout.write((char*)&iv,          sizeof(iv));
    fout.write((char*)&l_key_size,  sizeof(l_key_size));
    fout.write((char*)l_key.data(), l_key_size);
    fout.close();

    result.success = true;
    return result;
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
