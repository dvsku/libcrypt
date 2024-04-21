#include "libcrypt/rc4/rc4.hpp"

#include <fstream>
#include <sstream>

using namespace libcrypt;

///////////////////////////////////////////////////////////////////////////////
// INTERNAL

static const uint32_t KEY_FILE_MAGIC   = 0x20464B44;
static const uint32_t ENCRYPTION_MAGIC = 0x4B535644;

static std::string internal_parse_key(const char* key, size_t size);
static std::string internal_hex_string_to_string(const std::string& hex_string);

static void internal_swap(uint8_t* buffer, uint32_t i, uint32_t j);
static crypt_result internal_write(std::filesystem::path& output, const rc4::buffer_t& buffer);

static bool internal_has_magic(const rc4::buffer_t& buffer);
static void internal_write_magic(rc4::buffer_t& buffer);
static void internal_remove_magic(rc4::buffer_t& buffer);

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

    return magic == KEY_FILE_MAGIC;
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

    fout.write((char*)&KEY_FILE_MAGIC, sizeof(KEY_FILE_MAGIC));
    fout.write((char*)&iv,             sizeof(iv));
    fout.write((char*)&l_key_size,     sizeof(l_key_size));
    fout.write((char*)l_key.data(),    l_key_size);
    fout.close();

    result.success = true;
    return result;
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
    crypt_result result;

    if (internal_has_magic(buffer)) {
        result.message = "Buffer is already encrypted.";
        return result;
    }

    result = crypt(buffer);
    if (!result)
        return result;

    internal_write_magic(buffer);

    result.success = true;
    return result;
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
    crypt_result result;

    if (!internal_has_magic(buffer)) {
        result.message = "Not encrypted.";
        return result;
    }

    internal_remove_magic(buffer);
    return crypt(buffer);
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

bool internal_has_magic(const rc4::buffer_t& buffer) {
    if (buffer.size() < 4)
        return false;

    uint32_t magic = 0;
    std::memcpy(&magic, buffer.data(), 4);

    return magic == ENCRYPTION_MAGIC;
}

void internal_write_magic(rc4::buffer_t& buffer) {
    if (internal_has_magic(buffer)) return;

    buffer.resize(buffer.size() + 4);
    std::memmove(buffer.data() + 4, buffer.data(), buffer.size() - 4);
    std::memcpy(buffer.data(), &ENCRYPTION_MAGIC, 4);
}

void internal_remove_magic(rc4::buffer_t& buffer) {
    if (!internal_has_magic(buffer)) return;

    std::memmove(buffer.data(), buffer.data() + 4, buffer.size() - 4);
    buffer.resize(buffer.size() - 4);
}
