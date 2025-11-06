#!/bin/bash
clear
echo -e "Enter your filename to compile (for 580VNX only):"
read name
clear
python ./580vnx/compiler_.py -f hex < "./rsc_ropchain/$name.rsc"
