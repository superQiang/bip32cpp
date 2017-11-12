//
// Created by Will Skinner on 11/11/17.
//

#ifndef BIP32_EXTENDEDKEYPAIR_H
#define BIP32_EXTENDEDKEYPAIR_H

#include <cryptopp/integer.h>
#include <cryptopp/ecp.h>

class ExtendedKeyPair {
//public:
//    static const unsigned int private_testnet_version = 0x04358394;
//    static const unsigned int private_mainnet_version = 0x0488ADE4;
//    static const unsigned int public_testnet_version = 0x043587CF;
//    static const unsigned int public_mainnet_version = 0x0488B21E;
//
//private:
//    const CryptoPP::Integer privKey;
//    const CryptoPP::ECP::Point pubKey;
//    const byte chainCode[];
//    const byte depth;
//    const ExtendedKeyPair parent;
//    const unsigned int childNumber;
//    const bool isMainnet;
//
//public:
//    /**
//     * Each account is composed of two keypair chains: an internal and an external one. The external keychain is used
//     * to generate new public addresses, while the internal keychain is used for all other operations (change addresses,
//     * generation addresses, ..., anything that doesn't need to be communicated). Clients that do not support separate
//     * keychains for these should use the external one for everything.
//     *
//     * <p>
//     * m/iH/0/k corresponds to the k'th keypair of the external chain of account number i of the HDW derived from master m.
//     * m/iH/1/k corresponds to the k'th keypair of the internal chain of account number i of the HDW derived from master m.
//     * <p>
//     * The keyString may not be complete.
//     *
//     * @param keyString A string like /iH/0/k
//     */
//    ExtendedKeyPair generate(std::string keyString) const;
//
//    ExtendedKeyPair ckdPriv(unsigned int i) const;
//
//    ExtendedKeyPair neuter() const;
//
//    std::string serializePub() const;
//
//    std::string serializePriv() const;
//
//    static ExtendedKeyPair parseBase58Check(std::string base58Encoded) const;
//
//    class Builder {
//    private:
//        CryptoPP::Integer *privKey;
//        byte chainCode[];
//        bool isMainnet;
//        byte depth;
//        ExtendedKeyPair parent;
//        unsigned int childNumber;
//        byte fingerprint[];
//        CryptoPP::ECP::Point *pubKey;
//
//    public:
//        ExtendedKeyPair build();
//
//        Builder setPrivKey(const CryptoPP::Integer &privKey);
//
//        Builder setIsMainnet(bool isMainnet);
//
//        Builder setDepth(byte depth);
//
//        Builder setParent(const ExtendedKeyPair &parent);
//
//        Builder setChildNumber(unsigned int childNumber);
//
//        Builder setPubKey(const CryptoPP::ECP::Point &pubKey);
//    };
//
//
//private:
//    ExtendedKeyPair generateSubtree(std::vector<std::string> pathParts) const;
//
//    unsigned int parseIndex(std::string indexString) const;


};


#endif //BIP32_EXTENDEDKEYPAIR_H
