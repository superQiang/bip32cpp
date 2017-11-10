//
// Created by Will Skinner on 11/9/17.
//

#ifndef BIP32_BIP32_H
#define BIP32_BIP32_H

#include <cstdint>
#include <cryptopp/eccrypto.h>
#include <cryptopp/integer.h>

namespace BIP32 {
    typedef uint8_t byte;
}

class Bip32 {

public:


    static byte hash160[](const byte bytes[]);

    // point(p): returns the coordinate pair resulting from EC point multiplication (repeated application of the EC
    // group operation) of the secp256k1 base point with the integer p.
    static CryptoPP::ECP::Point CryptoPP::ECP::Point(const CryptoPP::Integer &p);

    // ser32(i): serialize a 32-bit unsigned integer i as a 4-byte sequence, most significant byte first.
    static byte ser32[](uint32_t i);

    static byte ser256[](const CryptoPP::Integer &p);

    static byte serP[](const CryptoPP::Integer &p);

    static CryptoPP::Integer parse256[](const byte bytes[]);
};


#endif //BIP32_BIP32_H
