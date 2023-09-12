#!/bin/bash
#set -x
devices=(iPhone2,1 iPhone3,1 iPhone3,3 iPhone4,1 iPad1,1 iPad2,1 iPad2,2 iPad2,3 iPad2,4 iPad3,1 iPad3,2 iPad3,3 iPod3,1 iPod4,1)

# generates kernel offsets, run after downloading and decrypting kernelcaches with scrape1.sh
jq="./tools/jq"

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

        if [[ $build == "8"* ]]; then
            ./coffit4.sh ../kernelcaches_dec/kc-${device_model}_${build}.dec ${device_model}_${build}
        else
            ./coffit5.sh ../kernelcaches_dec/kc-${device_model}_${build}.dec ${device_model}_${build}
        fi
    done
done
