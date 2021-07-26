#!/bin/bash

APP=ltntstools
GIT_VERSION=`git describe --abbrev=8 | sed 's!-.*!!g'`

mkdir -p tmp/bin
cp ../src/tstools_util tmp/bin
strip tmp/bin/tstools_util

mkdir -p tmp/man
cp ../man/*.8 tmp/man

pushd tmp/bin
	for BIN in `./tstools_util | grep ^tstools`
	do
		ln -sf tstools_util $BIN
	done
popd

cd tmp
zip ../$APP-osx-$GIT_VERSION.zip --symlinks -r .
cd ..
rm -rf tmp

