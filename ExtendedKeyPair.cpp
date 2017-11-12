//
// Created by Will Skinner on 11/11/17.
//

#include <assert.h>
#include "ExtendedKeyPair.h"

//ExtendedKeyPair ExtendedKeyPair::generate(std::string keyString) {
//    return ExtendedKeyPair();
//}
//
//Builder ExtendedKeyPair::Builder::setPrivKey(const CryptoPP::Integer &privKey) {
//    Builder::privKey = privKey;
//}
//
//Builder ExtendedKeyPair::Builder::setIsMainnet(bool isMainnet) {
//    Builder::isMainnet = isMainnet;
//}
//
//Builder ExtendedKeyPair::Builder::setDepth(byte depth) {
//    Builder::depth = depth;
//}
//
//Builder ExtendedKeyPair::Builder::setParent(const ExtendedKeyPair &parent) {
//    Builder::parent = parent;
//}
//
//Builder ExtendedKeyPair::Builder::setChildNumber(unsigned int childNumber) {
//    Builder::childNumber = childNumber;
//}
//
//Builder ExtendedKeyPair::Builder::setPubKey(const CryptoPP::ECP::Point &pubKey) {
//    Builder::pubKey = pubKey;
//}
//
//ExtendedKeyPair ExtendedKeyPair::Builder::build() {
//    assert (chainCode != NULL);
//
//    if (nullptr != privKey) {
//        pubKey = Bip32.point(privKey);
//    } else {
//        assert
//        pubKey != NULL;
//    }
//
//    if (parent != NULL) {
//        byte[]
//        pubKeyHash = Bip32.hash160(parent.pubKey);
//        fingerprint = Arrays.copyOfRange(pubKeyHash, 0, 4);
//    } else {
//        fingerprint = new byte[]{0, 0, 0, 0};
//    }
//
//    return new ExtendedKeyPair(this);
//}
