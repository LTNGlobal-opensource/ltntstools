#!/bin/bash

APP=ltntstools
SPECFILE=$APP.spec

rm -rf ~/rpmbuild

sudo yum -y install rpmdevtools rpmlint
rpmdev-setuptree

GIT_VERSION=`git describe --abbrev=8 | sed 's!-.*!!g'`

cat $SPECFILE  | sed "s/^Version.*$/Version:\t${GIT_VERSION}/g" > ~/rpmbuild/SPECS/$SPECFILE

cat ~/rpmbuild/SPECS/$SPECFILE

mkdir -p ~/rpmbuild/BUILDROOT/$APP-$GIT_VERSION-1.x86_64/usr/local/bin

cp ../src/tstools_util ~/rpmbuild/BUILDROOT/$APP-$GIT_VERSION-1.x86_64/usr/local/bin

pushd ~/rpmbuild/BUILDROOT/$APP-$GIT_VERSION-1.x86_64/usr/local/bin
	for BIN in `./tstools_util | grep ^tstools`
	do
		ln -sf tstools_util $BIN
	done
popd

rpmbuild -bb ~/rpmbuild/SPECS/$SPECFILE

mv /home/stoth/rpmbuild/RPMS/x86_64/$APP-$GIT_VERSION-1.x86_64.rpm .

# Test the RPM install on a clean centos system.
# We have a dep on libpcap, ensure yum finds the dep and installs it automatically for us.
# yum --nogpgcheck localinstall ltntstools-v1.0.1-1.x86_64.rpm

