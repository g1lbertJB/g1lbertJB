#!/bin/bash

# Compile script tested on: macOS 10.15, Ubuntu 20.04
PREFIX=/usr/local

limd() {
    install_name_tool -change $PREFIX/lib/libimobiledevice-1.0.6.dylib @executable_path/lib/libimobiledevice-1.0.6.dylib $1
    install_name_tool -change $PREFIX/lib/libusbmuxd-2.0.6.dylib @executable_path/lib/libusbmuxd-2.0.6.dylib $1
    install_name_tool -change $PREFIX/lib/libimobiledevice-glue-1.0.0.dylib @executable_path/lib/libimobiledevice-glue-1.0.0.dylib $1
    install_name_tool -change $PREFIX/lib/libplist-2.0.4.dylib @executable_path/lib/libplist-2.0.4.dylib $1
}

if [[ $(uname) == "Darwin" ]]; then
    if [[ ! -e $PREFIX/lib/libimobiledevice-1.0.6.dylib || ! -e deps ]]; then
        curl -LO https://gist.github.com/LukeZGD/ed69632435390be0e41c66620510a19c/raw/aea321877d651a3391c8884fbbd7cd32fd0a2e71/limd-build-macos.sh
        chmod +x limd-build-macos.sh
        ./limd-build-macos.sh
    fi

    patch -f configure.ac < configure.patch
    patch -f src/idevicebackup2.c src/idevicebackup2.patch

    LIBRESSL_VER=2.2.7
    DEPSDIR=$PREFIX
    LIBSSL=$DEPSDIR/lib/libssl.35.tbd
    LIBCRYPTO=$DEPSDIR/lib/libcrypto.35.tbd
    SDKDIR=`xcrun --sdk macosx --show-sdk-path 2>/dev/null`
    LIBCURL_VERSION=`/usr/bin/curl-config --version |cut -d " " -f 2`
    LIBXML2_VERSION=`/usr/bin/xml2-config --version |cut -d " " -f 2`
    LIMD_CFLAGS="-I$PREFIX/include"
    LIMD_LIBS="-L$PREFIX/lib -limobiledevice-1.0 -lplist-2.0"
    LIMD_VERSION=`cat $PREFIX/lib/pkgconfig/libimobiledevice-1.0.pc |grep Version: |cut -d " " -f 2`
    LIBPLIST_CFLAGS="-I$PREFIX/include"
    LIBPLIST_LIBS="-L$PREFIX/lib -lplist-2.0"
    LIBPLIST_VERSION=`cat $PREFIX/lib/pkgconfig/libplist-2.0.pc |grep Version: |cut -d " " -f 2`
    LIMD_GLUE_CFLAGS="-I$PREFIX/include"
    LIMD_GLUE_LIBS="-L$PREFIX/lib -limobiledevice-glue-1.0"
    LIMD_GLUE_VERSION=`cat $PREFIX/lib/pkgconfig/libimobiledevice-glue-1.0.pc |grep Version: |cut -d " " -f 2`
    LIBZIP_VERSION=1.7.1
    LIBZIP_DIR=libzip-$LIBZIP_VERSION
    LIBZIP_CFLAGS="-I$DEPSDIR/$LIBZIP_DIR/lib -I$DEPSDIR/$LIBZIP_DIR/build"
    LIBZIP_LIBS="$DEPSDIR/$LIBZIP_DIR/build/lib/libzip.a -Xlinker /usr/lib/libbz2.dylib -Xlinker /usr/lib/liblzma.dylib -lz"

    if [[ ! -e $PREFIX/libressl-$LIBRESSL_VER || ! -e $PREFIX/libzip-$LIBZIP_VERSION ]]; then
        sudo cp -R deps/libressl-$LIBRESSL_VER deps/libzip-$LIBZIP_VERSION deps/bin deps/lib deps/include $PREFIX
    fi

    ./autogen.sh \
      openssl_CFLAGS="-I$DEPSDIR/libressl-$LIBRESSL_VER/include" openssl_LIBS="-Xlinker $LIBSSL -Xlinker $LIBCRYPTO" openssl_VERSION="$LIBRESSL_VER" \
      libcurl_CFLAGS="-I$SDKDIR/usr/include" libcurl_LIBS="-lcurl" libcurl_VERSION="$LIBCURL_VERSION" \
      libzip_CFLAGS="$LIBZIP_CFLAGS" libzip_LIBS="$LIBZIP_LIBS" libzip_VERSION="$LIBZIP_VERSION" \
      zlib_CFLAGS="-I$SDKDIR/usr/include" zlib_LIBS="-lz" zlib_VERSION="1.2" \
      libimobiledevice_CFLAGS="$LIMD_CFLAGS" libimobiledevice_LIBS="$LIMD_LIBS" libimobiledevice_VERSION="$LIMD_VERSION" \
      libplist_CFLAGS="$LIBPLIST_CFLAGS" libplist_LIBS="$LIBPLIST_LIBS" libplist_VERSION="$LIBPLIST_VERSION" \
      limd_glue_CFLAGS="$LIMD_GLUE_CFLAGS" limd_glue_LIBS="$LIMD_GLUE_LIBS" limd_glue_VERSION="$LIMD_GLUE_VERSION"
    make clean
    make
    limd src/unthreadedjb
    rm -r output
    mkdir -p output/lib
    cp src/unthreadedjb output
    cp $PREFIX/lib/libimobiledevice-1.0.6.dylib $PREFIX/lib/libusbmuxd-2.0.6.dylib $PREFIX/lib/libimobiledevice-glue-1.0.0.dylib $PREFIX/lib/libplist-2.0.4.dylib output/lib
    echo "Done. unthreadedjb binary and libs are in output/"
    exit
fi

export CC_ARGS="CC=/usr/bin/gcc CXX=/usr/bin/g++ LD=/usr/bin/ld RANLIB=/usr/bin/ranlib AR=/usr/bin/ar"
export ALT_CC_ARGS="CC=/usr/bin/gcc CXX=/usr/bin/g++ LD=/usr/bin/ld RANLIB=/usr/bin/ranlib AR=/usr/bin/ar"
export CONF_ARGS="--disable-dependency-tracking --disable-silent-rules --prefix=/usr/local --disable-shared --enable-debug --without-cython"
export ALT_CONF_ARGS="--disable-dependency-tracking --disable-silent-rules --prefix=/usr/local"
export JNUM="-j$(nproc)"

if [[ ! -e $PREFIX/sbin/usbmuxd || ! -e $PREFIX/lib/libimobiledevice.a ]]; then
    sudo chown -R $USER: /usr/local

    sudo apt update
    sudo apt remove -y libssl-dev
    sudo apt install -y pkg-config libtool automake g++ cmake git libusb-1.0-0-dev libreadline-dev libpng-dev git autopoint aria2 ca-certificates

    git clone https://github.com/madler/zlib
    cd zlib
    ./configure --static
    make $JNUM LDFLAGS="$BEGIN_LDFLAGS"
    make install
    cd ..

    curl -LO https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz
    tar -zxvf bzip2-1.0.8.tar.gz
    cd bzip2-1.0.8
    make $JNUM
    make $JNUM install
    cd ..

    sslver="1.1.1v"
    curl -LO https://www.openssl.org/source/openssl-$sslver.tar.gz
    tar -zxvf openssl-$sslver.tar.gz
    cd openssl-$sslver
    if [[ $(uname -m) == "a"* && $(getconf LONG_BIT) == 64 ]]; then
        ./Configure no-ssl3-method linux-aarch64 "-Wa,--noexecstack -fPIC"
    elif [[ $(uname -m) == "a"* ]]; then
        ./Configure no-ssl3-method linux-generic32 "-Wa,--noexecstack -fPIC"
    else
        ./Configure no-ssl3-method enable-ec_nistp_64_gcc_128 linux-x86_64 "-Wa,--noexecstack -fPIC"
    fi
    make $JNUM depend
    make $JNUM
    make install_sw install_ssldirs
    rm -rf /usr/local/lib/libcrypto.so* /usr/local/lib/libssl.so*
    cd ..

    git clone https://github.com/lzfse/lzfse
    cd lzfse
    make $JNUM $ALT_CC_ARGS
    make $JNUM install
    cd ..

    curl -LO http://archive.ubuntu.com/ubuntu/pool/main/libp/libplist/libplist_2.1.0.orig.tar.bz2
    bzip2 -d libplist*.bz2
    tar -xvf libplist*.tar -C .
    cd libplist*/
    ./autogen.sh $CONF_ARGS $CC_ARGS
    make $JNUM
    make $JNUM install
    cd ..

    curl -LO http://archive.ubuntu.com/ubuntu/pool/main/libu/libusbmuxd/libusbmuxd_2.0.1.orig.tar.bz2
    bzip2 -d libusbmuxd*.bz2
    tar -xvf libusbmuxd*.tar -C .
    cd libusbmuxd*/
    ./autogen.sh $CONF_ARGS $CC_ARGS
    make $JNUM
    make $JNUM install
    cd ..

    curl -LO http://archive.ubuntu.com/ubuntu/pool/main/libi/libimobiledevice/libimobiledevice_1.2.1~git20191129.9f79242.orig.tar.bz2
    bzip2 -d libimobiledevice*.bz2
    tar -xvf libimobiledevice*.tar -C .
    cd libimobiledevice*/
    ./autogen.sh $CONF_ARGS $CC_ARGS LIBS="-L/usr/local/lib -lz -ldl"
    make $JNUM
    make $JNUM install
    cd ..

    curl -LO http://archive.ubuntu.com/ubuntu/pool/main/u/usbmuxd/usbmuxd_1.1.1~git20191130.9af2b12.orig.tar.gz
    tar -xvzf usbmuxd*.gz -C .
    cd usbmuxd*/
    ./autogen.sh $CONF_ARGS $CC_ARGS
    make $JNUM LDFLAGS="-Wl,--allow-multiple-definition"
    sudo make $JNUM install
    sudo chown -R $USER: /usr/local
    cd ..

    git clone https://github.com/nih-at/libzip
    cd libzip
    sed -i 's/\"Build shared libraries\" ON/\"Build shared libraries\" OFF/g' CMakeLists.txt
    cmake $CC_ARGS .
    make $JNUM
    make $JNUM install
    cd ..
fi

./autogen.sh
make clean
make LIBS="-ldl"
echo "Done. unthreadedjb binary is in src/"
