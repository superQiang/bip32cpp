#include <iostream>

//int main() {
//    std::cout << "Hello, World!" << std::endl;
//    return 0;
//}

// g++ -g3 -O2 cryptopp-ec-compress.cpp -o cryptopp-ec-compress.exe -lcryptopp -pthread

#include <iostream>
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include <cryptopp/filters.h>
using CryptoPP::StringSource;
using CryptoPP::StringSink;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;

#include <cryptopp/sha.h>
using CryptoPP::SHA1;

#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/eccrypto.h>
using CryptoPP::ECP;
using CryptoPP::ECDSA;

#include <cryptopp/oids.h>
using CryptoPP::ASN1::secp160r1;

int main(int argc, char* argv[])
{
    AutoSeededRandomPool prng;

    // Generate a private key, and two public keys.
    //   One with and one without compression
    ECDSA<ECP, SHA1>::PrivateKey privateKey;
    privateKey.Initialize(prng, secp160r1());

    ECDSA<ECP, SHA1>::PublicKey publicKey1;
    privateKey.MakePublicKey(publicKey1);

    ECDSA<ECP, SHA1>::PublicKey publicKey2;
    privateKey.MakePublicKey(publicKey2);
    publicKey2.AccessGroupParameters().SetPointCompression(true);

    // Save the public keys
    string p1, p2;
    publicKey1.Save(StringSink(p1).Ref());
    publicKey2.Save(StringSink(p2).Ref());

    //////////////////////////////////////////////////////////////////////
    // Print some stuff about them
    string s3, s4;
    StringSource ss3(p1, true, new HexEncoder(new StringSink(s3)));
    StringSource ss4(p2, true, new HexEncoder(new StringSink(s4)));

    cout << "Key 1 (not compressed): " << p1.size() << " bytes" << endl;
    cout << "  " << s3 << endl;
    cout << "Key 2 (compressed): " << p2.size() << " bytes" << endl;
    cout << "  " << s4 << endl;
    cout << endl;

    //////////////////////////////////////////////////////////////////////
    // Two new keys to load up the persisted keys
    ECDSA<ECP, SHA1>::PublicKey publicKey3, publicKey4;
    publicKey4.AccessGroupParameters().SetPointCompression(true);

    publicKey3.Load(StringSource(p1, true).Ref());
    publicKey4.Load(StringSource(p2, true).Ref());

    // And validate them
    publicKey3.Validate(prng, 3);
    publicKey4.Validate(prng, 3);

    // Get the public elemnts of the loaded keys
    const ECP::Point& y3 = publicKey3.GetPublicElement();
    const Integer& y3_x = y3.x;
    const Integer& y3_y = y3.y;

    const ECP::Point& y4 = publicKey4.GetPublicElement();
    const Integer& y4_x = y4.x;
    const Integer& y4_y = y4.y;

    // Print some stuff about them
    cout << "Key 3 (after deserialization of Key 1):" << endl;
    cout << "  y3.x: " << std::hex << y3_x << endl;
    cout << "  y3.y: " << std::hex << y3_y << endl;
    cout << "Key 4 (after deserialization of Key 2):" << endl;
    cout << "  y4.x: " << std::hex << y4_x << endl;
    cout << "  y4.y: " << std::hex << y4_y << endl;
    cout << endl;

    //////////////////////////////////////////////////////////////////////
    // Two new keys to load up the persisted keys, but crossing wires
    //   so there's a compress/uncompressed mismatch
    ECDSA<ECP, SHA1>::PublicKey publicKey5, publicKey6;
    publicKey6.AccessGroupParameters().SetPointCompression(true);

    // This should be `p1`
    publicKey5.Load(StringSource(p2, true).Ref());
    // This should be `p2`
    publicKey6.Load(StringSource(p1, true).Ref());

    // Get the public elemnts of the loaded keys
    const ECP::Point& y5 = publicKey5.GetPublicElement();
    const Integer& y5_x = y5.x;
    const Integer& y5_y = y5.y;

    const ECP::Point& y6 = publicKey6.GetPublicElement();
    const Integer& y6_x = y6.x;
    const Integer& y6_y = y6.y;

    // Print some stuff about them
    cout << "Key 5 (after deserialization of Key 1):" << endl;
    cout << "  y5.x: " << std::hex << y5_x << endl;
    cout << "  y5.y: " << std::hex << y5_y << endl;
    cout << "Key 6 (after deserialization of Key 2):" << endl;
    cout << "  y6.x: " << std::hex << y6_x << endl;
    cout << "  y6.y: " << std::hex << y6_y << endl;
    cout << endl;

    return 0;
}
