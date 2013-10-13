#!/bin/bash
function copy {
    mkdir -p tree/$2/var/unthreadedjb
    cp -v ./$1/obj/$1 tree/$2/var/unthreadedjb/jb
    cp -v ./static/amfi.dylib tree/$2/var/unthreadedjb/amfi.dylib
    cp -v ./static/launchd.conf tree/$2/var/unthreadedjb/launchd.conf
}

rm -rf tree

DEVICES="N90 N92 K48 N81 N88 N18"
REVISIONS="9B176 9A334 9A405 9B206 8L1 8K2"

for i in $DEVICES; do
    for j in $REVISIONS; do
        copy ${i}_${j} ${j}_${i}AP
    done;
done;

copy N90_9B208 9B208_N90AP
copy K93_9B176 9B176_K93AP
copy K93_9B206 9B206_K93AP
