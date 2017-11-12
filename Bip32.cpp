//
// Created by Will Skinner on 11/9/17.
//

#include "Bip32.h"
#include <cryptopp/ripemd.h>
#include <assert.h>

using namespace BIP32;
using namespace CryptoPP;

// Statics
CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> *Bip32::params;

CryptoPP::ECP *Bip32::curve;

// Not thread safe
DL_GroupParameters_EC<ECP> &Bip32::getParams() {
    if (nullptr == Bip32::params) {
        Bip32::params = new DL_GroupParameters_EC<ECP>(ASN1::secp256k1());
    }

    assert(nullptr != Bip32::params);
    return *Bip32::params;
}

// Not thread safe
ECP &Bip32::getCurve() {
    if (nullptr == Bip32::params) {
        Bip32::curve = const_cast<ECP *>(&getParams().GetCurve());
    }

    assert(nullptr != Bip32::curve);
    return *Bip32::curve;
}

// end statics

void
Bip32::hash160(byte destination[], const byte *bytes, unsigned int datalen) {
    byte shaDigest[SHA256::DIGESTSIZE];
    SHA256().CalculateDigest(shaDigest, bytes, datalen);

    RIPEMD160().CalculateDigest(destination, shaDigest, SHA256::DIGESTSIZE);
}

void
Bip32::ser256(byte destination[], const Integer &p) {
    p.Encode(destination, 256);
}

void
Bip32::serP(byte destination[], const ECP::Point &point) {
    getCurve().EncodePoint(destination, point, true);
}

Integer
Bip32::parse256(const byte *bytes) {
    Integer *i = new Integer();
    i->Decode(bytes, 256);
    return *i;
}

void
Bip32::ser32(byte destination[], uint32_t i) {
    destination[0] = static_cast<byte>((i & 0xff000000) >> 24);
    destination[1] = static_cast<byte>((i & 0x00ff0000) >> 16);
    destination[2] = static_cast<byte>((i & 0x0000ff00) >> 8);
    destination[3] = static_cast<byte>((i & 0x000000ff));
}

ECP::Point
Bip32::Point(const Integer &p) {
    return getCurve().Multiply(p, getParams().GetSubgroupGenerator());
}
