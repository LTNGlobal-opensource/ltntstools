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

