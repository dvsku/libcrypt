#include <libcrypt.hpp>
#include <gtest/gtest.h>

using namespace libcrypt;

TEST(md5, hashing) {
    const char plaintext[5] = { 'd', 'v', 's', 'k', 'u' };
    md5 md5;

    auto hash = md5.compute(plaintext, 5);

    EXPECT_TRUE(hash[0]  == 0xe7);
    EXPECT_TRUE(hash[1]  == 0x78);
    EXPECT_TRUE(hash[2]  == 0x3f);
    EXPECT_TRUE(hash[3]  == 0x21);
    EXPECT_TRUE(hash[4]  == 0x2e);
    EXPECT_TRUE(hash[5]  == 0xcb);
    EXPECT_TRUE(hash[6]  == 0x54);
    EXPECT_TRUE(hash[7]  == 0x99);
    EXPECT_TRUE(hash[8]  == 0x5a);
    EXPECT_TRUE(hash[9]  == 0x79);
    EXPECT_TRUE(hash[10] == 0x89);
    EXPECT_TRUE(hash[11] == 0x29);
    EXPECT_TRUE(hash[12] == 0x32);
    EXPECT_TRUE(hash[13] == 0xab);
    EXPECT_TRUE(hash[14] == 0xb5);
    EXPECT_TRUE(hash[15] == 0xa4);
}

TEST(md5, hash_to_string) {
    const char plaintext[5] = { 'd', 'v', 's', 'k', 'u' };
    md5 md5;
    
    auto hash     = md5.compute(plaintext, 5);
    auto hash_str = md5.to_string(hash);

    EXPECT_TRUE(hash_str == "e7783f212ecb54995a79892932abb5a4");
}