#!/bin/bash
#set -x
devices=(iPhone2,1 iPhone3,1 iPhone3,3 iPhone4,1 iPad1,1 iPad2,1 iPad2,2 iPad2,3 iPad2,4 iPad3,1 iPad3,2 iPad3,3 iPod3,1 iPod4,1)

# downloads and decrypts 4.2.6-5.1.1 kernelcaches for devices listed above
# also generates Makefile
# make sure to have jq, pzb, xpwntool in PATH
jq="$(which jq)"
pzb="$(which pzb)"
xpwntool="$(which xpwntool)"
mkdir ../kernelcaches ../kernelcaches_dec 2>/dev/null

printf 'include theos/makefiles/common.mk

SUBPROJECTS=' > Makefile

for device in ${devices[@]}; do
    echo $device
    json=$(curl "https://firmware-keys.ipsw.me/device/$device")
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
        echo ${device_model}_${build}
        url="$(curl https://api.ipsw.me/v2.1/$device/$build/url)"
        $pzb -g "kernelcache.release.$(echo $device_model | tr '[:upper:]' '[:lower:]')" -o "kc-${device_model}_${build}" "$url"
        mv "kc-${device_model}_${build}" ../kernelcaches/

        device_fw_key="$(curl https://api.m1sta.xyz/wikiproxy/$device/$build)"
        iv=$(echo $device_fw_key | $jq -j '.keys[] | select(.image | startswith("Kernelcache")) | .iv')
        key=$(echo $device_fw_key | $jq -j '.keys[] | select(.image | startswith("Kernelcache")) | .key')
        echo "xpwntool kernelcaches/kc-${device_model}_${build} kernelcaches_dec/kc-${device_model}_${build}.dec -iv $iv -k $key"
        $xpwntool ../kernelcaches/kc-${device_model}_${build} ../kernelcaches_dec/kc-${device_model}_${build}.dec -iv $iv -k $key

        printf "${device_model}_${build} " >> Makefile
    done
done

printf '\n\ninclude $(THEOS_MAKE_PATH)/aggregate.mk\n' >> Makefile
