#!/usr/bin/env bash

clean_usbmuxd() {
    if [[ $platform != "linux" ]]; then
        return
    fi
    sudo killall -9 usbmuxd usbmuxd2 2>/dev/null
    sleep 1
    if [[ $(command -v systemctl) ]]; then
        sudo systemctl restart usbmuxd
    elif [[ $(command -v rc-service) ]]; then
        sudo rc-service usbmuxd start
    fi
}

if [[ $OSTYPE == "linux"* ]]; then
    platform="linux"
    trap "clean_usbmuxd" EXIT
    trap "exit 1" INT TERM
fi

cd "$(dirname "$0")"

if [[ $platform == "linux" ]]; then
    echo "[Log] Enter your user password when prompted"
    if [[ $(command -v systemctl) ]]; then
        sudo systemctl stop usbmuxd
    elif [[ $(command -v rc-service) ]]; then
        sudo rc-service usbmuxd zap
    else
        sudo killall -9 usbmuxd usbmuxd2
    fi
    echo "[Log] Running usbmuxd"
    sudo -b ./usbmuxd -pf &>./usbmuxd.log
    sleep 1
elif [[ $(uname) == "Darwin" ]]; then
    xattr -cr *
fi

echo "[Log] Running g1lbertJB"
./gilbertjb
clean_usbmuxd
echo "You may now close this window."
read -s
