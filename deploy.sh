#!/bin/sh
scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -P 2222 mvm_hv_vmx64.ko root@127.0.0.1:/root/mvm_hv_vmx64.ko
