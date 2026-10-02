#!/bin/bash

APP=ltntstools
SPECFILE=$APP.spec

rm -rf ~/rpmbuild

which rpmdev-setuptree >/dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "Aborting, please install rpm dev tools with:"
	echo "     sudo yum -y install rpmdevtools rpmlint"
	exit 1
fi
rpmdev-setuptree

GIT_VERSION=`git describe --abbrev=8 | sed 's!-.*!!g'`

cat $SPECFILE  | sed "s/^Version.*$/Version:\t${GIT_VERSION}/g" > ~/rpmbuild/SPECS/$SPECFILE

TARGET_DIR=~/rpmbuild/BUILDROOT/$APP-$GIT_VERSION-1.x86_64

# CMake build directories (see README.md). Override if yours differ.
BUILD_DIR=${BUILD_DIR:-../build}
DEPS_DIR=`cd ${DEPS_DIR:-../build-deps} && pwd` || exit 1
DEPS_LIB=$DEPS_DIR/target-root/usr/lib

# The packaged binary must find its bundled libraries in
# /usr/local/lib-ltntstools, not in the build machine's deps directory.
# CMake applies this RPATH at install time.
cmake -S .. -B $BUILD_DIR -DLTNTSTOOLS_DEPS_DIR=$DEPS_DIR \
	-DLTNTSTOOLS_INSTALL_RPATH='$ORIGIN/../lib-ltntstools' || exit 1
cmake --build $BUILD_DIR || exit 1

# Installs tstools_util and all of its tstools_* symlinks.
cmake --install $BUILD_DIR --prefix $TARGET_DIR/usr/local || exit 1
strip $TARGET_DIR/usr/local/bin/tstools_util

mkdir -p $TARGET_DIR/usr/local/share/man/man8
cp ../man/*.8 $TARGET_DIR/usr/local/share/man/man8

# Keep in sync with %files and __requires_exclude in the spec file.
LIBS="libdvbpsi.so.10 libklscte35.so.0 libltntstools.so.0 libsrt.so.1.4
      libjson-c.so.4 libzvbi.so.0 libklvanc.so.0
      libavformat.so.58 libavutil.so.56 libavcodec.so.58
      libswresample.so.3 libswscale.so.5
      libssl.so.3 libcrypto.so.3"

mkdir -p $TARGET_DIR/usr/local/lib-ltntstools
for LIB in $LIBS
do
	cp $DEPS_LIB/$LIB $TARGET_DIR/usr/local/lib-ltntstools/$LIB || exit 1
done
if [ -f $DEPS_LIB/libntt.so.0 ]; then
	cp $DEPS_LIB/libntt.so.0 $TARGET_DIR/usr/local/lib-ltntstools/libntt.so.0
fi

# Optional tools are packaged only if this build produced them
# (ENABLE_DTAPI / ENABLE_NTT); see the matching %if blocks in the spec file.
WITH_DTAPI=0
WITH_NTT=0
[ -L $TARGET_DIR/usr/local/bin/tstools_asi2ip ] && WITH_DTAPI=1
[ -L $TARGET_DIR/usr/local/bin/tstools_ntt_inspector ] && WITH_NTT=1

rpmbuild -bb --define "with_dtapi $WITH_DTAPI" --define "with_ntt $WITH_NTT" \
	~/rpmbuild/SPECS/$SPECFILE || exit 1

mv ~/rpmbuild/RPMS/x86_64/$APP-$GIT_VERSION-1.x86_64.rpm .

# Test the RPM install on a clean centos system.
# We have a dep on libpcap, ensure yum finds the dep and installs it automatically for us.
# yum --nogpgcheck localinstall ltntstools-v1.0.1-1.x86_64.rpm

# Extract the change log rpm -qp --changelog ~/rpmbuild/RPMS/x86_64/$APP-$GIT_VERSION-1.x86_64.rpm

#cp $APP-$GIT_VERSION-1.x86_64.rpm docker
