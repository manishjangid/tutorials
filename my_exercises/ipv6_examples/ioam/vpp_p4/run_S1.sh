#!/bin/bash
echo "Enabling simple_switch on S1"
simple_switch -i 1@l_S11 -i 2@l_S12 --pcap --thrift-port 9090 --nanolog ipc:///tmp/bm-0-log.ipc ./build/ioam_demo.p4.json --log-console –debugger &

echo "Configure entries on S1"
./configure_switch_entries.py ./s1-commands.txt 9090




