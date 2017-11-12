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
    string expected = "751e76e8199196d454941c45d1b3a323f1433bd6";

    unsigned int size = Bip32::getCurve().EncodedPointSize(true);
    byte serBasePoint[size];
    fill_n(serBasePoint, size, 0);
    Bip32::serP(serBasePoint, Bip32::getParams().GetSubgroupGenerator());

    byte actual[RIPEMD160::DIGESTSIZE];
    Bip32::hash160(actual, serBasePoint, size);
    string actualString = bytes_to_hex_string(actual, RIPEMD160::DIGESTSIZE);

    REQUIRE(expected == actualString);
}

TEST_CASE("Integer serialization", "[ser32]") {
    unsigned int i = 1 << 31;
    byte expected[4] = {0x80, 0x0, 0x0, 0x0};
    byte actual[4];
    Bip32::ser32(actual, i);

    for (int i = 0; i < 4; i++) {
        REQUIRE(expected[i] == actual[i]);
    }

    i = 0;
    byte expected2[4] = {0x0, 0x0, 0x0, 0x0};
    byte actual2[4];
    Bip32::ser32(actual2, i);

    for (int i = 0; i < 4; i++) {
        REQUIRE(expected2[i] == actual2[i]);
    }

    i = 0xffffffff;
    byte expected3[4] = {0xff, 0xff, 0xff, 0xff};
    byte actual3[4];
    Bip32::ser32(actual3, i);

    for (int i = 0; i < 4; i++) {
        REQUIRE(expected3[i] == actual3[i]);
    }
}

TEST_CASE("Parse private master key", "parseBase58Check") {
    string priv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
}
