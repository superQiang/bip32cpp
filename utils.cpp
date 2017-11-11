//
// Created by Will Skinner on 11/10/17.
//

#include <string>
#include <sstream>
#include <iomanip>
#include "Bip32.h"
using namespace BIP32;

std::string bytes_to_hex_string(const byte *bytes, unsigned int length) {
    std::ostringstream oss;
    for (unsigned int i = 0; i < length; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
    }
    return oss.str();
}
