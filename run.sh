#!/bin/bash
clear
echo -e "Enter your filename to compile (for 580VNX only):"
read name
clear
python main.py -f hex 580vnx < "./rsc_ropchain/$name.rsc"
