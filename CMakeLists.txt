cmake_minimum_required(VERSION 3.8)
if (POLICY CMP0025)
    cmake_policy(SET CMP0025 NEW)
endif ()

project(bip32)

set(CMAKE_CXX_STANDARD 17)

link_directories(/usr/local/lib)
link_libraries(cryptopp)

set(SOURCE_FILES Bip32.cpp Bip32.h Bip32Tests.cpp utils.cpp utils.h ExtendedKeyPair.cpp ExtendedKeyPair.h)
add_executable(bip32 ${SOURCE_FILES})