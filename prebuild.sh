#!/bin/bash

function valid
{
    if [ $? -ne 0 ]; then
        exit 1
    fi
}

# prepare submodules
echo "Prepare submodules"
git submodule update --init --recursive

cd depends
# build obliv-c
echo "Build Obliv-c"
cd obliv-c
./configure && make
valid
cd ..

# build labhe
echo "Build labhe"
cd labhe
cd KeccakCodePackage
make generic64/libkeccak.a
valid
cd ..
mkdir build && cd build && cmake ..
make
valid
cd ..

cd ..