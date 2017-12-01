#!/bin/bash
CXX=/usr/bin/g++-7 
CC=/usr/bin/cc
cmake -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_C_COMPILER=$CC .
make
