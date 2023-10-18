#!/bin/bash
#set -x

koffset4=./tools/koffset4
make_kernel_patchfile=./tools/make_kernel_patchfile
apply_patchfile=./tools/apply_patchfile

if [[ -z $1 || -z $2 ]]; then
    echo "Usage: ./coffit4.sh <decrypted kernelcache> <folder name>"
    exit 1
fi

mkdir $2 2>/dev/null
pushd $2 >/dev/null
ln -sf ../common/kernel_code4.S kernel_code.S
ln -sf ../Makefile.common Makefile
ln -sf ../common/pwn4.m pwn.m
popd >/dev/null

echo "# $2" > $2/offsets.mk
$koffset4 $1 >> $2/offsets.mk
cat $2/offsets.mk | tr '[:lower:]' '[:upper:]' | sed 's|0X|0x|g' | tee $2/offsets.mk

$make_kernel_patchfile $1 patchfile
test=$(
    $apply_patchfile $1 patchfile patched |
    tr -d ')' |
    tr '[:lower:]' '[:upper:]' |
    sed 's|0X|0x|g' |
    sed 's|VM_MAP_ENTER (|KERNEL_VM_MAP_ENTER = |g' |
    sed 's|VM_MAP_PROTECT (|KERNEL_VM_MAP_PROTECT = |g' |
    sed 's|AMFI (|KERNEL_AMFI_BINARY_CACHE = |g' |
    sed 's|TASK_FOR_PID 0 (|KERNEL_TASK_FOR_PID = |g' |
    sed 's|CS_ENFORCEMENT_DISABLE (|KERNEL_CS_ENFORCEMENT_DISABLE = |g' |
    sed 's|PROC_ENFORCE (|KERNEL_PROC_ENFORCE = |g' |
    sed 's|SB_EVALUATE (|KERNEL_SANDBOX = |g' |
    sed '/USB POWER/d' |
    sed '/-DEBUG_ENABLED INITIALIZER/d' |
    sed '/SB_EVALUATE HOOK/d'
)

echo "$test" | tr -d ' ' > tmpset
test=$(echo "$test" | sed '/KERNEL_SANDBOX/d')
source tmpset

# debug enabled offset is not outputted by apply_patchfile, but it is in the patch file itself
thing="$(xxd -p patchfile)"
search="2B64656275675F656E61626C6564" # +debug_enabled
search=$(echo $search | tr '[:upper:]' '[:lower:]')
v=$(echo $thing | grep -o "$search.*" | cut -c 29- | cut -c -8)
KERNEL_DEBUG_ENABLED=0x$(echo ${v:6:2}${v:4:2}${v:2:2}${v:0:2} | tr '[:lower:]' '[:upper:]') # reverse endianness

# weird attempt of getting sandbox offset manually:
# search "0000024AFFFFFF6C000000100000024B" on hex editor
# select the third FF and get its offset (example: 939CA6)
# add 0x80 at the start: 0x80939CA6

# auto find sandbox offset (add E0A to sb_evaluate)
SANDBOX_ADD="0xE0A"
KERNEL_SANDBOX=$(printf "0x%X" $((KERNEL_SANDBOX+SANDBOX_ADD)))

echo "$test" | tee -a $2/offsets.mk
echo "KERNEL_DEBUG_ENABLED = $KERNEL_DEBUG_ENABLED" | tee -a $2/offsets.mk
echo "KERNEL_SANDBOX = $KERNEL_SANDBOX" | tee -a $2/offsets.mk

rm patchfile patched tmpset
