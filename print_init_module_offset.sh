#!/bin/sh
readelf -s mvm_hv_vmx64.ko | grep --color=never init_module | cut -d' ' -f6
