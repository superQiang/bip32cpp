//
// Created by Will Skinner on 11/11/17.
//

#include <sstream>
#include <assert.h>
#include "ExtendedKeyPair.h"
#include "Bip32.h"
#include <cryptopp/ripemd.h>

using namespace CryptoPP;
using namespace BIP32;
using namespace std;

optional <ExtendedKeyPair> ExtendedKeyPair::generate(std::string keyString) {
    if (depth != 0) {
        return nullopt;
    }

    vector<string> parts = split(keyString, '/');
    assert(parts[0] == 'm');

    if (parts.size() == 1) {
        return optional < ExtendedKeyPair > {this};
    }

    return optional<ExtendedKeyPair>(generateSubtree(parts), 1);
}

ExtendedKeyPair ExtendedKeyPair::generateSubtree(std::vector<std::string> pathParts, unsigned int index = 1) const {
    if (pathParts.size() - index == 1) {
        return this;
    }

    unsigned int index = parseIndex(pathParts[index]);
    ExtendedKeyPair nextSubtree = ckdPriv(index);
    return nextSubtree.generateSubtree(pathParts, index + 1);
}

Builder ExtendedKeyPair::Builder::setPrivKey(const CryptoPP::Integer &privKey) {
    this->privKey = const_cast<CryptoPP::Integer *>(&privKey);
    return *this;
}

Builder ExtendedKeyPair::Builder::setIsMainnet(bool isMainnet) {
    this->isMainnet = isMainnet;
    return *this;
}

Builder ExtendedKeyPair::Builder::setDepth(byte depth) {
    this->depth = depth;
    return *this;
}

Builder ExtendedKeyPair::Builder::setParent(const ExtendedKeyPair &parent) {
    this->parent = const_cast<ExtendedKeyPair *> (&parent);
    return *this;
}

Builder ExtendedKeyPair::Builder::setChildNumber(unsigned int childNumber) {
    this->childNumber = childNumber;
    return *this;
}

Builder ExtendedKeyPair::Builder::setPubKey(const CryptoPP::ECP::Point &pubKey) {
    this->pubKey = const_cast<ECP::Point *> (&pubKey);
    return *this;
}

ExtendedKeyPair ExtendedKeyPair::Builder::build() {
    assert (chainCode != nullptr);

    if (nullptr != privKey) {
        pubKey = &Bip32::Point(*privKey);
    } else {
        assert(pubKey != nullptr);
    }

    if (nullptr != parent) {
        byte serPub[33];
        Bip32::serP(serPub, *pubKey);

        byte pubKeyHash[RIPEMD160::DIGESTSIZE];
        Bip32::hash160(pubKeyHash, serPub, 33);
        fingerprint = {pubKeyHash[0], pubKeyHash[1], pubKeyHash[2], pubKeyHash[3]};
    } else {
        fingerprint = new byte[]{0, 0, 0, 0};
    }

    return *new ExtendedKeyPair(this);
}

ExtendedKeyPair::ExtendedKeyPair(ExtendedKeyPair::Builder *builder) {
    this->pubKey = *builder->pubKey;
    this->privKey = *builder->privKey;
    this->chainCode = builder->chainCode;
    this->depth = builder->depth;
    this->parent = builder->parent;
    this->childNumber = builder->childNumber;
    this->isMainnet = builder->isMainnet;
}

vector<string> ExtendedKeyPair::split(string &str, char delimiter) {
    vector<string> parts;
    stringstream ss(str);
    string item;

    while (getline(ss, item, delimiter)) {
        parts.push_back(item);
    }

    return parts;
}

unsigned int ExtendedKeyPair::parseIndex(std::string indexString) const {
    unsigned int value;
    value = static_cast<unsigned int>(stoi(indexString.substr(0, indexString.size() - 1)));

    if (indexString.find_first_of("hH") != string::npos) {
        value |= 0x80000000;
    }

    return value;
}

