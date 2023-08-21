#!/bin/bash

libtoolize
aclocal
autoconf
autoheader
automake -a -c
autoreconf -i
./configure --disable-dependency-tracking
