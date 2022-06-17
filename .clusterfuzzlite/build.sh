#!/bin/bash -eux
echo "CC: $CC"
echo "CXX: $CXX"
echo "LIB_FUZZING_ENGINE: $LIB_FUZZING_ENGINE"
echo "CFLAGS: $CFLAGS"
echo "CXXFLAGS: $CXXFLAGS"

# Install dependencies
./contrib/ci/run --deps-only

# Build project with -fsanitize=fuzzer-no-link in CFLAGS
source contrib/fedora/bashrc_sssd
pushd contrib/ci/
. configure.sh
popd
reconfig --enable-static --with-smb-idmap-interface-version=5
make

# Link to the fuzzer with -fsanitize=fuzzer
$CC $CFLAGS $SRC/sssd/src/fuzz/sssd_fuzzer.c -I $SRC/sssd/src/ $SRC/sssd/x86_64/.libs/libsss_util.a -lunistring -o sssd_fuzzer $LIB_FUZZING_ENGINE

# Copy outputs
cp -v sssd_fuzzer $OUT/
