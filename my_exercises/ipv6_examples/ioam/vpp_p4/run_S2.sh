#!/bin/bash
echo "Enabling simple_switch on S2"
simple_switch -i 1@l_S21 -i 2@l_S22 --pcap --thrift-port 9090 --nanolog ipc:///tmp/bm-0-log.ipc ./build/ioam_demo.p4.json --log-console –debugger &

echo "Configure entries on S2"
./configure_switch_entries.py ./s2-commands.txt 9090




