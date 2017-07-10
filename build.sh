#!/bin/bash

export CFLAGS="-I$HOME/target-root/include"
export LDFLAGS="-L$HOME/target-root/lib"
./configure --prefix=$HOME/target-root --enable-shared=no
