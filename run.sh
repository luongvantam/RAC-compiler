#!/bin/bash
clear
echo -e "Enter your filename to compile (for 580VNX only):"
read name
clear
python ./580vnx/compiler_.py -f hex < ./580vnx/$name # giả sử file asm trong folder 580vnx
while true; do
    sleep 10
done
