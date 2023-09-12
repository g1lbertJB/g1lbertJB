#!/bin/bash
#set -x

koffset=./tools/koffset
make_kernel_patchfile=./tools/make_kernel_patchfile
apply_patchfile=./tools/apply_patchfile

if [[ -z $1 || -z $2 ]]; then
    echo "Usage: ./coffit5.sh <decrypted kernelcache> <folder name>"
    exit 1
fi

mkdir $2 2>/dev/null
pushd $2 >/dev/null
ln -sf ../common/kernel_code.S kernel_code.S
ln -sf ../Makefile.common Makefile
ln -sf ../common/pwn.m pwn.m
popd >/dev/null

echo "# $2" > $2/offsets.mk
$koffset $1 >> $2/offsets.mk
cat $2/offsets.mk | tr '[:lower:]' '[:upper:]' | sed 's|0X|0x|g' | tee $2/offsets.mk
