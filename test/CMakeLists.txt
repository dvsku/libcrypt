INCLUDE_DIRECTORIES("${CRYPT_HEADERS}")
INCLUDE_DIRECTORIES("${GTEST_INCLUDES}")

INCLUDE(GoogleTest)

LINK_LIBRARIES(libcrypt)
LINK_LIBRARIES(GTest::gtest_main)

ADD_EXECUTABLE(test_md5
	"test_md5.cpp"
)

gtest_discover_tests(test_md5)

ADD_EXECUTABLE(test_rc4
	"test_rc4.cpp"
)

gtest_discover_tests(test_rc4)