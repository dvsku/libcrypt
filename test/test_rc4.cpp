#include <libcrypt.hpp>
#include <gtest/gtest.h>

using namespace libcrypt;

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