#!/bin/bash

set -ex

echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
echo 0 | sudo tee /proc/sys/kernel/kptr_restrict
echo off | sudo tee /sys/devices/system/cpu/smt/control 
source /opt/openenclave/share/openenclave/openenclaverc
cd ~/sgx-pte-mod/spy-kernel/
make clean
make remake
cd ~/sgx-pte-mod/spy-user/helloworld/
make clean
make
make run

