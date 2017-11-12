//
// Created by Will Skinner on 11/9/17.
//

#ifndef BIP32_BIP32_H
#define BIP32_BIP32_H

#include <cstdint>
#include <cryptopp/eccrypto.h>
#include <cryptopp/integer.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>

namespace BIP32 {
    typedef uint8_t byte;
}

// Bitcoin uses SECP256K1 - object id 1.3.132.0.10
class Bip32 {

private:
    static CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> *params;

    static CryptoPP::ECP *curve;

public:
    static CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> &getParams();

    static CryptoPP::ECP &getCurve();

public:
    // Compute ripemd160(sha256(bytes)) and store the result in destination
    static void hash160(byte destination[], const byte bytes[], unsigned int datalen);

    // point(p): returns the coordinate pair resulting from EC point multiplication (repeated application of the EC
    // group operation) of the secp256k1 base point with the integer p.
    static CryptoPP::ECP::Point &Point(const CryptoPP::Integer &p);

    // ser32(i): serialize a 32-bit unsigned integer i as a 4-byte sequence, most significant byte first.
    static void ser32(byte destination[], uint32_t i);

    // Serialize p into destionation, most significant byte first.
    static void ser256(byte destination[], const CryptoPP::Integer &p);

    // Serialize using SEC1's compressed form
    static void serP(byte destination[], const CryptoPP::ECP::Point &point);

    static CryptoPP::Integer parse256(const byte bytes[]);
};


#endif //BIP32_BIP32_H
