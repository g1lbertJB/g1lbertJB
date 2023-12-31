#!/bin/bash
#set -x
devices=(iPhone2,1 iPhone3,1 iPhone3,3 iPhone4,1 iPad1,1 iPad2,1 iPad2,2 iPad2,3 iPad2,4 iPad3,1 iPad3,2 iPad3,3 iPod3,1 iPod4,1)

# pack the untether binaries in tars, run after scrape1.sh, scrape2.sh, and make
# make sure to have jq in PATH
jq="$(which jq)"
mkdir tars 2>/dev/null

for device in ${devices[@]}; do
    echo $device
    json=$(curl "https://firmware-keys.ipsw.me/device/$device")
    device_type=$device
    case $device in
        iPhone2,1 ) device_model=N88;;
        iPhone3,1 ) device_model=N90;;
        iPhone3,3 ) device_model=N92;;
        iPhone4,1 ) device_model=N94;;
        iPad1,1 ) device_model=K48;;
        iPad2,1 ) device_model=K93;;
        iPad2,2 ) device_model=K94;;
        iPad2,3 ) device_model=K95;;
        iPad2,4 ) device_model=K93a;;
        iPad3,1 ) device_model=J1;;
        iPad3,2 ) device_model=J2;;
        iPad3,3 ) device_model=J2a;;
        iPod3,1 ) device_model=N18;;
        iPod4,1 ) device_model=N81;;
    esac
    device_model_lower=$(echo $device_model | tr  '[:upper:]' '[:lower:]')

    len=$(echo "$json" | $jq length)
    builds=()
    i=0
    while (( i < len )); do
        j=$(echo "$json" | $jq -r ".[$i].buildid")
        if [[ $j == "8"* || $j == "9"* ]] && [[ $j != "8A"* && $j != "8B"* && $j != "8C"* ]]; then
            builds+=("$j")
        fi
        ((i++))
    done

    for build in ${builds[@]}; do
        newtar="${device_type}_${build}"
        echo $newtar

        mkdir -p $newtar/private/etc $newtar/private/var/unthreadedjb $newtar/usr/libexec payload/${build}_${device_model}AP
        cp static/amfi.dylib $newtar/private/var/unthreadedjb
        cp static/launchd.conf $newtar/private/etc
        cp static/dirhelper $newtar/usr/libexec
        cp ${device_model}_${build}/obj/${device_model}_${build} payload/${build}_${device_model}AP/jb
        cp ${device_model}_${build}/obj/${device_model}_${build} $newtar/private/var/unthreadedjb/jb
        chmod +x $newtar/private/var/unthreadedjb/* $newtar/usr/libexec/*
        ./mktar.sh $newtar
        mv $newtar.tar tars/$newtar.tar
        rm -r $newtar
    done
done
