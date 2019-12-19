#!/bin/bash
glibtoolize
aclocal
autoconf
autoheader
automake -a -c
autoreconf -i
./configure --disable-dependency-tracking

# Only doing this here because some people don't know git clone --recursive is a thing.
if [ -d "theos" ]; then
cd theos && git pull
cd ..
else
echo "Installing theos dependency"
git clone https://github.com/theos/theos
fi

echo "Compiling..."

sudo make
sudo make install

echo "Packing the jailbreak and its components..."

if [ -d "yeet" ]; then # Not overriding to save past changes, if new commits cause issues with compiling.
echo "Folder yeet already exists. Please remove the folder and run this script again." && exit
else
mkdir yeet
fi

cp -rv src/unthreadedjb yeet/
cp -rv payload yeet/

tar cvfz pris0nbarake.tar.gz yeet

echo "Done :D"
