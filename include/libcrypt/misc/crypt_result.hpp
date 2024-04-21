#pragma once

#include <string>

namespace libcrypt {
    class crypt_result {
    public:
        bool        success = false;
        std::string message = "";

    public:
        explicit operator bool() const {
            return success;
        }
    };
}