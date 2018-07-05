#!/bin/bash

export CFLAGS="-I$PWD/../ltntstools-libdvbpsi/root/include -I$PWD/../ltntstools-ffmpeg/root/include"
export LDFLAGS="-L$PWD/../ltntstools-libdvbpsi/root/lib -I$PWD/../ltntstools-ffmpeg/root/lib"
./configure --prefix=$HOME/target-root --enable-shared=no
