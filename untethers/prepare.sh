#!/bin/bash

pushd /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS7.1.sdk/System/Library/Frameworks/IOKit.framework
sudo ln -s Versions/A/IOKit .
popd

git clone https://github.com/xerub/ldid
pushd ldid
./mk.sh
sudo mkdir /usr/local/bin 2>/dev/null
sudo cp ldid /usr/local/bin
popd
