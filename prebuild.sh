#!/bin/bash

# prepare submodules
echo "Prepare submodules"
git submodule update --init --recursive

# build obliv-c
echo "Build Obliv-c"
cd obliv-c
./configure && make
cd ..

# build labhe
echo "Build labhe"
cd labhe
cd KeccakCodePackage
make generic64/libkeccak.a
cd ..
mkdir build && cd build && cmake ..
make
cd ..