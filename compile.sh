#!/bin/bash

# Compile script tested on: macOS 10.11, Ubuntu 22.04, Windows 10 LTSC 21H2
PREFIX=/usr/local

limd() {
    install_name_tool -change $PREFIX/lib/libimobiledevice-1.0.6.dylib @executable_path/lib/libimobiledevice-1.0.6.dylib $1
    install_name_tool -change $PREFIX/lib/libusbmuxd-2.0.6.dylib @executable_path/lib/libusbmuxd-2.0.6.dylib $1
    install_name_tool -change $PREFIX/lib/libimobiledevice-glue-1.0.0.dylib @executable_path/lib/libimobiledevice-glue-1.0.0.dylib $1
    install_name_tool -change $PREFIX/lib/libplist-2.0.4.dylib @executable_path/lib/libplist-2.0.4.dylib $1
}

mkdir -p output/payload tmp
cp -R payload/* output/payload/
cp LICENSE README.md output/

if [[ $(uname) == "Darwin" ]]; then
    if [[ ! -d limd ]]; then
        mkdir limd
        pushd limd
        curl -LO https://gist.github.com/LukeZGD/0f5ba45494912c419f59bd8178ab57bd/raw/41612817e2df4722d5c9cf34e760442ee48bb024/limd-build-macos.sh
        chmod +x limd-build-macos.sh
        ./limd-build-macos.sh
        popd
    fi

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
    LIBZIP_DIR=libzip
    LIBZIP_CFLAGS="-I$DEPSDIR/$LIBZIP_DIR/lib -I$DEPSDIR/$LIBZIP_DIR/build"
    LIBZIP_LIBS="$DEPSDIR/$LIBZIP_DIR/build/lib/libzip.a -Xlinker $SDKDIR/usr/lib/libbz2.tbd -Xlinker $SDKDIR/usr/lib/liblzma.tbd -lz"

    if [[ ! -e $PREFIX/libressl-$LIBRESSL_VER || ! -e $PREFIX/libzip ]]; then
        sudo cp -R limd/deps/libressl-$LIBRESSL_VER limd/deps/libzip limd/deps/bin limd/deps/lib limd/deps/include $PREFIX
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
    mkdir -p output/lib
    cp src/unthreadedjb output/gilbertjb
    cp limd/bin/lib/libimobiledevice-1.0.6.dylib limd/bin/lib/libusbmuxd-2.0.6.dylib limd/bin/lib/libimobiledevice-glue-1.0.0.dylib limd/bin/lib/libplist-2.0.4.dylib output/lib
    cp gilbertjb.command output/
    echo "Done. output is in output/"
    exit

elif [[ $OSTYPE == "cygwin" ]]; then
    pacman -Syu --noconfirm
    pacman -S --needed --noconfirm mingw-w64-x86_64-clang mingw-w64-x86_64-libzip mingw-w64-x86_64-brotli mingw-w64-x86_64-libpng mingw-w64-x86_64-python mingw-w64-x86_64-libunistring mingw-w64-x86_64-curl mingw-w64-x86_64-cython mingw-w64-x86_64-cmake
    pacman -S --needed --noconfirm make automake autoconf pkg-config openssl libtool m4 libidn2 git libunistring libunistring-devel python cython python-devel unzip zip
    export CC=gcc
    export CXX=g++
    export BEGIN_LDFLAGS="-Wl,--allow-multiple-definition"

    pushd tmp

    git clone https://github.com/libimobiledevice/libplist
    git clone https://github.com/libimobiledevice/libimobiledevice-glue
    git clone https://github.com/libimobiledevice/libusbmuxd
    git clone https://github.com/libimobiledevice/libtatsu
    git clone https://github.com/libimobiledevice/libimobiledevice

    gzver="1.13"
    curl -LO https://ftp.wayne.edu/gnu/gzip/gzip-$gzver.zip
    echo "Building gzip..."
    unzip -d . gzip-$gzver.zip
    cd gzip-$gzver
    ./configure
    make
    cd ..

    echo "Building libplist..."
    cd libplist
    ./autogen.sh --without-cython
    make $JNUM install LDFLAGS="$BEGIN_LDFLAGS"
    cd ..

    echo "Building libimobiledevice-glue..."
    cd libimobiledevice-glue
    ./autogen.sh
    make $JNUM install LDFLAGS="$BEGIN_LDFLAGS"
    cd ..

    echo "Building libusbmuxd..."
    cd libusbmuxd
    ./autogen.sh
    make $JNUM install LDFLAGS="$BEGIN_LDFLAGS"
    cd ..

    echo "Building libtatsu..."
    cd libtatsu
    ./autogen.sh
    make $JNUM install LDFLAGS="$BEGIN_LDFLAGS"
    cd ..

    echo "Building libimobiledevice..."
    cd libimobiledevice
    ./autogen.sh --without-cython
    make $JNUM install LDFLAGS="$BEGIN_LDFLAGS"
    cd ..

    popd

    ./autogen.sh
    make $JNUM install LDFLAGS="$BEGIN_LDFLAGS" LIBS="-lcrypto"

    mkdir output
    cp tmp/gzip-$gzver/gzip.exe output/
    cp src/.libs/unthreadedjb.exe output/gilbertjb.exe
    cp /mingw64/bin/libcrypto-3-x64.dll output/
    cp /mingw64/bin/libimobiledevice-1.0.dll output/
    cp /mingw64/bin/libimobiledevice-glue-1.0.dll output/
    cp /mingw64/bin/libplist-2.0.dll output/
    cp /mingw64/bin/libssl-3-x64.dll output/
    cp /mingw64/bin/libusbmuxd-2.0.dll output/

    echo "Done. output is in output/"
    exit
fi

export CC_ARGS="CC=/usr/bin/gcc CXX=/usr/bin/g++ LD=/usr/bin/ld RANLIB=/usr/bin/ranlib AR=/usr/bin/ar"
export ALT_CC_ARGS="CC=/usr/bin/gcc CXX=/usr/bin/g++ LD=/usr/bin/ld RANLIB=/usr/bin/ranlib AR=/usr/bin/ar"
export CONF_ARGS="--disable-dependency-tracking --disable-silent-rules --prefix=/usr/local --disable-shared --enable-debug --without-cython"
export ALT_CONF_ARGS="--disable-dependency-tracking --disable-silent-rules --prefix=/usr/local"
export JNUM="-j$(nproc)"

if [[ ! -e $PREFIX/lib/libimobiledevice.a ]]; then
    sudo chown -R $USER: /usr/local

    sudo apt update
    sudo apt remove -y libssl-dev
    sudo apt install -y pkg-config libtool automake g++ cmake git libusb-1.0-0-dev libreadline-dev libpng-dev libcurl4-openssl-dev git autopoint ca-certificates

    git clone https://github.com/madler/zlib
    git clone https://github.com/lzfse/lzfse
    git clone https://github.com/libimobiledevice/libplist
    git clone https://github.com/libimobiledevice/libimobiledevice-glue
    git clone https://github.com/libimobiledevice/libusbmuxd
    git clone https://github.com/libimobiledevice/libtatsu
    git clone https://github.com/libimobiledevice/libimobiledevice
    git clone https://github.com/nih-at/libzip
    curl -LO https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz

    cd zlib
    ./configure --static
    make $JNUM LDFLAGS="$BEGIN_LDFLAGS"
    make install
    cd ..

    tar -zxvf bzip2-1.0.8.tar.gz
    cd bzip2-1.0.8
    make $JNUM
    make $JNUM install
    cd ..

    if [[ ! -e $PREFIX/lib/libcrypto.a || ! -e $PREFIX/lib/libssl.a ]]; then
        sslver="1.1.1w"
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
    fi

    cd lzfse
    make $JNUM $ALT_CC_ARGS
    make $JNUM install
    cd ..

    cd libplist
    ./autogen.sh $CONF_ARGS $CC_ARGS
    make $JNUM
    make $JNUM install
    cd ..

    cd libimobiledevice-glue
    ./autogen.sh $CONF_ARGS $CC_ARGS
    make $JNUM
    make $JNUM install
    cd ..

    cd libusbmuxd
    ./autogen.sh $CONF_ARGS $CC_ARGS
    make $JNUM
    make $JNUM install
    cd ..

    cd libtatsu
    ./autogen.sh $CONF_ARGS $CC_ARGS
    make $JNUM
    make $JNUM install
    cd ..

    cd libimobiledevice
    ./autogen.sh $CONF_ARGS $CC_ARGS LIBS="-L/usr/local/lib -lz -ldl"
    make $JNUM
    make $JNUM install
    cd ..

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

cp src/unthreadedjb output/gilbertjb
cp gilbertjb.command output/
if [[ ! -s output/usbmuxd ]]; then
    platform_arch="$(uname -m)"
    if [[ $(uname -m) == "a"* && $(getconf LONG_BIT) == 64 ]]; then
        platform_arch="arm64"
    fi
    curl -L https://github.com/LukeZGD/Legacy-iOS-Kit/raw/refs/heads/main/bin/linux/$platform_arch/usbmuxd -o output/usbmuxd
fi
chmod +x output/usbmuxd
echo "Done. output is in output/"
