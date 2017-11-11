//
// Created by Will Skinner on 11/9/17.
//

#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file

#include <cstdio>
#include <cryptopp/ripemd.h>
#include "utils.h"
#include "catch.hpp"
#include "Bip32.h"

using namespace std;
using namespace CryptoPP;
using namespace BIP32;

TEST_CASE("Pretty printing bytes", "[bytes_to_hex_string]") {
    string expected = "101010";
    byte actualRaw[3] = {0x10, 0x10, 0x10};
    REQUIRE(expected == bytes_to_hex_string(actualRaw, 3));

    expected = "";
    byte actualRaw2[0] = {};
    REQUIRE(expected == bytes_to_hex_string(actualRaw2, 0));

    expected = "ffffff";
    byte actualRaw3[3] = {0xff, 0xff, 0xff};
    REQUIRE(expected == bytes_to_hex_string(actualRaw3, 3));
}

TEST_CASE("Hash160", "[hash160]") {
    auto *bip32 = new Bip32();
    string expected = "751e76e8199196d454941c45d1b3a323f1433bd6";

    unsigned int size = bip32->getCurve().EncodedPointSize(true);
    byte serBasePoint[size];
    fill_n(serBasePoint, size, 0);
    bip32->serP(serBasePoint, bip32->getParams().GetSubgroupGenerator());
    cout << bip32->getParams().GetSubgroupGenerator().x;

    byte actual[RIPEMD160::DIGESTSIZE];
    bip32->hash160(actual, serBasePoint, size);
    string actualString = bytes_to_hex_string(actual, RIPEMD160::DIGESTSIZE);

    REQUIRE(expected == actualString);
}
