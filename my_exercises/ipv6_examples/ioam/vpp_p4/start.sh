#!/bin/bash

sudo ./launch_lxc.sh -n host1 -t vpp-p4-ext -l 2
sudo ./launch_lxc.sh -n a -t vpp-p4-ext -l 2
sudo ./launch_lxc.sh -n S1 -t vpp-p4-ext -l 2
sudo ./launch_lxc.sh -n b -t vpp-p4-ext -l 2
sudo ./launch_lxc.sh -n S2 -t vpp-p4-ext -l 2
sudo ./launch_lxc.sh -n c -t vpp-p4-ext -l 2
sudo ./launch_lxc.sh -n host2 -t vpp-p4-ext -l 2
sudo ./connect_lxc.sh -c ./example/simple_p4_vpp_ip6/config.txt -f ./example/simple_p4_vpp_ip6/connect.log
lxc-attach -n a -- vpp unix { log /tmp/vpp.log full-coredump startup-config /scratch/example/simple_p4_vpp_ip6/a.conf cli-listen localhost:5002 }
#lxc-attach -n S1 -- vpp unix { log /tmp/vpp.log full-coredump startup-config /scratch/example/simple_p4_vpp_ip6/s1.conf cli-listen localhost:5002 }
lxc-attach -n b -- vpp unix { log /tmp/vpp.log full-coredump startup-config /scratch/example/simple_p4_vpp_ip6/b.conf cli-listen localhost:5002 }
#lxc-attach -n S2 -- vpp unix { log /tmp/vpp.log full-coredump startup-config /scratch/example/simple_p4_vpp_ip6/s2.conf cli-listen localhost:5002 }
lxc-attach -n c -- vpp unix { log /tmp/vpp.log full-coredump startup-config /scratch/example/simple_p4_vpp_ip6/c.conf cli-listen localhost:5002 }
lxc-attach -n host1 -- ip -6 address add db00::2/64 dev l_host11
lxc-attach -n host1 -- ip -6 route add default via db00::1
lxc-attach -n host2 -- ip -6 address add db05::2/64 dev l_host21
lxc-attach -n host2 -- ip -6 route add default via db05::1

