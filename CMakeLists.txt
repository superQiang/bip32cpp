cmake_minimum_required(VERSION 3.8)
project(bip32)

set(CMAKE_CXX_STANDARD 17)

set(SOURCE_FILES main.cpp Bip32.cpp Bip32.h)
add_executable(bip32 ${SOURCE_FILES})