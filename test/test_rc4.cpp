#include <libcrypt.hpp>
#include <gtest/gtest.h>

using namespace libcrypt;

static bool compare_buffers(const std::vector<uint8_t>& b1, const std::vector<uint8_t>& b2) {
    if (b1.size() != b2.size())
        return false;

    return std::equal(b1.begin(), b1.end(), b2.begin());
}

TEST(rc4, key_setting) {
    rc4 rc4;

    EXPECT_TRUE(rc4.get_key() == "");

    {
        const char key[5] = { 'd', 'v', 's', 'k', 'u' };
        rc4.set_key(key, 5);
    }

    EXPECT_TRUE(rc4.get_key() == "dvsku");

    rc4.set_key("");
    EXPECT_TRUE(rc4.get_key() == "");

    {
        std::string key = "dvsku";
        rc4.set_key(key);
    }

    EXPECT_TRUE(rc4.get_key() == "dvsku");

    {
        std::string key = "0x6476736B75";
        rc4.set_key(key);
    }

    EXPECT_TRUE(rc4.get_key() == "dvsku");
}

TEST(rc4, iv_setting) {
    rc4 rc4;

    EXPECT_TRUE(rc4.get_iv() == 0);
    
    rc4.set_iv(132);
    EXPECT_TRUE(rc4.get_iv() == 132);
}

TEST(rc4, buffer_encrypt_decrypt_ok) {
    rc4 rc4;

    std::vector<uint8_t> v1{
        0x03, 0x48, 0xA7, 0x8, 0x54, 0xBA, 0x99, 0xF7, 0x73, 0x11
    };
    std::vector<uint8_t> v2 = v1;

    rc4.set_key("testing");
    rc4.set_iv(91);

    rc4.encrypt_buffer(v2);
    rc4.decrypt_buffer(v2);

    EXPECT_TRUE(compare_buffers(v1, v2));

    rc4.encrypt_buffer(v2);
    rc4.decrypt_buffer(v2);

    EXPECT_TRUE(compare_buffers(v1, v2));
}

TEST(rc4, buffer_encrypt_decrypt_fail_wrong_iv) {
    rc4 rc4;

    std::vector<uint8_t> v1{
        0x03, 0x48, 0xA7, 0x8, 0x54, 0xBA, 0x99, 0xF7, 0x73, 0x11
    };
    std::vector<uint8_t> v2 = v1;

    rc4.set_key("testing");
    rc4.set_iv(91);

    rc4.encrypt_buffer(v2);

    rc4.set_iv(92);
    rc4.decrypt_buffer(v2);

    EXPECT_FALSE(compare_buffers(v1, v2));
}

TEST(rc4, buffer_encrypt_decrypt_fail_wrong_key) {
    rc4 rc4;

    std::vector<uint8_t> v1{
        0x03, 0x48, 0xA7, 0x8, 0x54, 0xBA, 0x99, 0xF7, 0x73, 0x11
    };
    std::vector<uint8_t> v2 = v1;

    rc4.set_key("testing");
    rc4.set_iv(91);

    rc4.encrypt_buffer(v2);

    rc4.set_key("testing2");
    rc4.decrypt_buffer(v2);

    EXPECT_FALSE(compare_buffers(v1, v2));
}

TEST(rc4, buffer_encrypt_decrypt_stream_ok) {
    rc4 rc4;

    std::vector<uint8_t> v1{
        0x03, 0x48, 0xA7, 0x8, 0x54, 0xBA, 0x99, 0xF7, 0x73, 0x11
    };
    std::vector<uint8_t> v2 = v1;

    rc4.set_key("testing");
    rc4.set_iv(91);

    rc4.encrypt_stream(&v2[0], 5, 0);
    rc4.encrypt_stream(&v2[5], 5, 5);
    rc4.reset();

    rc4.decrypt_stream(&v2[0], 5, 0);
    rc4.decrypt_stream(&v2[5], 5, 5);
    rc4.reset();

    EXPECT_TRUE(compare_buffers(v1, v2));
}
