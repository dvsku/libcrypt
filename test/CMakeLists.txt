INCLUDE_DIRECTORIES("${CRYPT_HEADERS}")
INCLUDE_DIRECTORIES("${GTEST_INCLUDES}")

INCLUDE(GoogleTest)

LINK_LIBRARIES(libcrypt)
LINK_LIBRARIES(GTest::gtest_main)

#ADD_EXECUTABLE(test_v1_packing
#	"v1/test_packing.cpp"
#)
#
#gtest_discover_tests(test_v1_packing)
