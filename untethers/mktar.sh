#!/bin/bash
if [[ -z $1 ]]; then
    echo "Usage: ./mktar.sh <folder to pack>"
    exit 1
fi
BASEDIR=$1/
tar --owner=root --group=wheel -cf "$1.tar" --exclude=.DS_Store -C "${BASEDIR}" .
