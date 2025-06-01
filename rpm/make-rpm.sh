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

mkdir -p $TARGET_DIR/usr/local/bin
cp ../src/tstools_util $TARGET_DIR/usr/local/bin
strip $TARGET_DIR/usr/local/bin/tstools_util

mkdir -p $TARGET_DIR/usr/local/share/man/man8
cp ../man/*.8 $TARGET_DIR/usr/local/share/man/man8

mkdir -p $TARGET_DIR/usr/local/lib-ltntstools
cp ../../target-root/usr/lib/libdvbpsi.so.10    $TARGET_DIR/usr/local/lib-ltntstools/libdvbpsi.so.10
cp ../../target-root/usr/lib/libklscte35.so.0   $TARGET_DIR/usr/local/lib-ltntstools/libklscte35.so.0
cp ../../target-root/usr/lib/libltntstools.so.0 $TARGET_DIR/usr/local/lib-ltntstools/libltntstools.so.0
cp ../../target-root/usr/lib64/libsrt.so.1.4    $TARGET_DIR/usr/local/lib-ltntstools/libsrt.so.1.4
cp ../../target-root/usr/lib/libjson-c.so.4     $TARGET_DIR/usr/local/lib-ltntstools/libjson-c.so.4
cp ../../target-root/usr/lib/libzvbi.so.0       $TARGET_DIR/usr/local/lib-ltntstools/libzvbi.so.0
cp ../../target-root/usr/lib/libklvanc.so.0     $TARGET_DIR/usr/local/lib-ltntstools/libklvanc.so.0
cp ../../target-root/usr/lib/libavformat.so.58  $TARGET_DIR/usr/local/lib-ltntstools/libavformat.so.58
cp ../../target-root/usr/lib/libavutil.so.56    $TARGET_DIR/usr/local/lib-ltntstools/libavutil.so.56
cp ../../target-root/usr/lib/libavcodec.so.58   $TARGET_DIR/usr/local/lib-ltntstools/libavcodec.so.58
cp ../../target-root/usr/lib/libswresample.so.3 $TARGET_DIR/usr/local/lib-ltntstools/libswresample.so.3
cp ../../target-root/usr/lib/libswscale.so.5    $TARGET_DIR/usr/local/lib-ltntstools/libswscale.so.5
cp ../../target-root/usr/lib/libntt.so.0        $TARGET_DIR/usr/local/lib-ltntstools/libntt.so.0

pushd $TARGET_DIR/usr/local/bin
	for BIN in `./tstools_util | grep ^tstools`
	do
		ln -sf tstools_util $BIN
	done
popd

rpmbuild -bb ~/rpmbuild/SPECS/$SPECFILE

mv ~/rpmbuild/RPMS/x86_64/$APP-$GIT_VERSION-1.x86_64.rpm .

# Test the RPM install on a clean centos system.
# We have a dep on libpcap, ensure yum finds the dep and installs it automatically for us.
# yum --nogpgcheck localinstall ltntstools-v1.0.1-1.x86_64.rpm

# Extract the change log rpm -qp --changelog ~/rpmbuild/RPMS/x86_64/$APP-$GIT_VERSION-1.x86_64.rpm

#cp $APP-$GIT_VERSION-1.x86_64.rpm docker
