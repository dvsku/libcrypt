#include "libcrypt/rc4/rc4.hpp"

#include <fstream>
#include <sstream>

using namespace libcrypt;

///////////////////////////////////////////////////////////////////////////////
// INTERNAL

static std::string internal_parse_key(const char* key, size_t size);
static std::string internal_hex_string_to_string(const std::string& hex_string);

static void internal_swap(uint8_t* buffer, uint32_t i, uint32_t j);
static crypt_result internal_write(std::filesystem::path& output, const rc4::buffer_t& buffer);

///////////////////////////////////////////////////////////////////////////////
// PUBLIC

rc4::rc4() {
    reset();

    m_key = "";
    m_iv  = 0U;
}

void rc4::reset() {
    m_initialized = false;
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

crypt_result rc4::encrypt_file(const file_path_t& input, const file_path_t& output) {
    buffer_t buffer;
    
    auto result = encrypt_file(input, buffer);
    if (!result)
        return result;

    file_path_t output_path = output == "" ? input : output;
    return internal_write(output_path, buffer);
}

crypt_result rc4::encrypt_file(const file_path_t& input, buffer_t& out) {
    crypt_result result;

    if (!std::filesystem::exists(input)) {
        result.message = "Input file not found.";
        return result;
    }

    std::ifstream fin(input, std::ios::binary | std::ios::in | std::ios::ate);
    if (!fin.is_open()) {
        result.message = "Failed to open input file.";
        return result;
    }

    size_t size = (size_t)fin.tellg();
    out.resize(size);
    fin.seekg(0, std::ios::beg);

    if (!fin.read((char*)out.data(), size)) {
        result.message = "Failed to read input file.";
        return result;
    }

    fin.close();

    return encrypt_buffer(out);
}

crypt_result rc4::encrypt_buffer(buffer_t& buffer) {
    return crypt(buffer);
}

crypt_result rc4::encrypt_stream(uint8_t* ptr, size_t size, size_t offset) {
    return crypt(ptr, size, offset, true);
}

crypt_result rc4::decrypt_file(const file_path_t& input, const file_path_t& output) {
    buffer_t buffer;

    auto result = decrypt_file(input, buffer);
    if (!result)
        return result;

    file_path_t output_path = output == "" ? input : output;
    return internal_write(output_path, buffer);
}

crypt_result rc4::decrypt_file(const file_path_t& input, buffer_t& out) {
    crypt_result result;

    if (!std::filesystem::exists(input)) {
        result.message = "Input file not found.";
        return result;
    }

    std::ifstream fin(input, std::ios::binary | std::ios::in | std::ios::ate);
    if (!fin.is_open()) {
        result.message = "Failed to open input file.";
        return result;
    }

    size_t size = (size_t)fin.tellg();
    out.resize(size);
    fin.seekg(0, std::ios::beg);

    if (!fin.read((char*)out.data(), size)) {
        result.message = "Failed to read input file.";
        return result;
    }

    fin.close();

    return decrypt_buffer(out);
}

crypt_result rc4::decrypt_buffer(buffer_t& buffer) {
    return crypt(buffer);
}

crypt_result rc4::decrypt_stream(uint8_t* ptr, size_t size, size_t offset) {
    return crypt(ptr, size, offset, true);
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE

void rc4::generate_box() {
    m_index_A         = 0;
    m_index_B         = 0;
    m_previous_offset = 0;

    for (uint32_t i = 0; i < 256; i++) {
        m_box[i] = (uint8_t)(m_iv ^ 0xFF);

        m_iv = m_iv == 0xFF ? 0x00 : m_iv + 1;
    }

    uint8_t mod = m_key.size() <= 0xFF ? (uint8_t)m_key.size() : 0xFF;

    uint32_t j = 0;
    for (uint32_t i = 0; i < 256; i++) {
        j += m_box[i];
        j += m_key[i % mod];
        j %= 256;

        internal_swap(m_box, i, j);
    }

    m_initialized = true;
}

crypt_result rc4::crypt(rc4::buffer_t& buffer) {
    return crypt(buffer.data(), buffer.size(), false);
}

crypt_result rc4::crypt(uint8_t* ptr, size_t size, size_t offset, bool keep_box) {
    crypt_result result;

    if (!m_initialized)
        generate_box();

    if (keep_box && offset != m_previous_offset) {
        generate_box();

        for (uint64_t i = 0; i < offset; i++) {
            m_index_A = (m_index_A + 1) % 256;
            m_index_B = (m_index_B + m_box[m_index_A]) % 256;
            internal_swap(m_box, m_index_A, m_index_B);
        }
    }

    for (uint64_t i = 0; i < size; i++) {
        m_index_A = (m_index_A + 1) % 256;
        m_index_B = (m_index_B + m_box[m_index_A]) % 256;
        internal_swap(m_box, m_index_A, m_index_B);
        ptr[i] = m_box[(m_box[m_index_A] + m_box[m_index_B]) % 256] ^ ptr[i];
    }

    if (!keep_box)
        m_initialized = false;
    else
        m_previous_offset += size;

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

void internal_swap(uint8_t* buffer, uint32_t i, uint32_t j) {
    uint8_t temp = buffer[i];
    buffer[i]    = buffer[j];
    buffer[j]    = temp;
}

crypt_result internal_write(std::filesystem::path& output, const rc4::buffer_t& buffer) {
    crypt_result result;

    std::filesystem::path dir_path(output);
    dir_path.remove_filename();

    if (!std::filesystem::is_directory(dir_path)) {
        std::filesystem::create_directories(dir_path);
        std::filesystem::permissions(dir_path, std::filesystem::perms::all);
    }

    std::ofstream out(output, std::ios::binary | std::ios::out);

    if (!out.is_open()) {
        result.message = "Failed to open output file.";
        return result;
    }

    out.write((char*)buffer.data(), buffer.size());
    out.close();

    result.success = true;
    return result;
}
