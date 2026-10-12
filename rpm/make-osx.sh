#!/bin/bash

# Package the CMake build (see README.md) as a self-contained zip:
#
#   bin/  tstools_util and its tstools_* symlinks
#   lib/  every non-system dylib it needs, found via @rpath
#   man/  man pages

APP=ltntstools
GIT_VERSION=`git describe --abbrev=8 | sed 's!-.*!!g'`

# CMake build directories. Override if yours differ.
BUILD_DIR=${BUILD_DIR:-../build}
DEPS_DIR=`cd ${DEPS_DIR:-../build-deps} && pwd` || exit 1

STAGE=$PWD/tmp
rm -rf $STAGE

# The packaged binary finds its dylibs in ../lib relative to itself.
cmake -S .. -B $BUILD_DIR -DLTNTSTOOLS_DEPS_DIR=$DEPS_DIR \
	-DLTNTSTOOLS_INSTALL_RPATH='@executable_path/../lib' || exit 1
cmake --build $BUILD_DIR || exit 1

# Installs tstools_util and all of its tstools_* symlinks.
cmake --install $BUILD_DIR --prefix $STAGE || exit 1

mkdir -p $STAGE/man
cp ../man/*.8 $STAGE/man

# Non-system libraries referenced by a Mach-O file. The deps build records
# absolute install names, so anything outside the OS is a build-tree path.
bundled_deps() {
	otool -L "$1" | tail -n +2 | awk '{print $1}' | grep -vE '^(/usr/lib/|/System/|@)'
}

# Copy the full dependency closure into lib/.
mkdir -p $STAGE/lib
CHANGED=1
while [ $CHANGED -eq 1 ]; do
	CHANGED=0
	for FILE in $STAGE/bin/tstools_util $STAGE/lib/*.dylib; do
		[ -f "$FILE" ] || continue
		for DEP in `bundled_deps $FILE`; do
			NAME=`basename $DEP`
			if [ ! -f $STAGE/lib/$NAME ]; then
				cp $DEP $STAGE/lib/$NAME || exit 1
				chmod u+w $STAGE/lib/$NAME
				CHANGED=1
			fi
		done
	done
done

# Point every reference at @rpath. Dylibs resolve @rpath through the
# executable's LC_RPATH (@executable_path/../lib).
for FILE in $STAGE/bin/tstools_util $STAGE/lib/*.dylib; do
	ARGS=""
	case $FILE in
	*.dylib) ARGS="-id @rpath/`basename $FILE`" ;;
	esac
	for DEP in `bundled_deps $FILE`; do
		ARGS="$ARGS -change $DEP @rpath/`basename $DEP`"
	done
	# Warns that the signature is invalidated; it is re-signed below.
	install_name_tool $ARGS $FILE 2>/dev/null || exit 1
done

strip $STAGE/bin/tstools_util
strip -x $STAGE/lib/*.dylib

# Editing Mach-O files invalidates their signatures, and arm64 refuses to run
# unsigned code, so re-sign everything (ad hoc).
codesign --force -s - $STAGE/lib/*.dylib $STAGE/bin/tstools_util || exit 1

# Nothing may still point at the build machine.
for FILE in $STAGE/bin/tstools_util $STAGE/lib/*.dylib; do
	if [ -n "`bundled_deps $FILE`" ]; then
		echo "Unbundled dependency left in $FILE:"
		bundled_deps $FILE
		exit 1
	fi
done
$STAGE/bin/tstools_util 2>&1 | grep -q '^Version:' || {
	echo "Packaged tstools_util does not run"
	exit 1
}

cd $STAGE
zip ../$APP-macos-$GIT_VERSION.zip --symlinks -r .
cd ..
rm -rf $STAGE

echo "Install with:"
echo "sudo unzip ../$APP-macos-$GIT_VERSION.zip -d /usr/local"
