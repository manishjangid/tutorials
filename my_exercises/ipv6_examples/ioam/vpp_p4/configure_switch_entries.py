#!/usr/bin/python
import subprocess
import sys

def read_entries(filename):
	entries = []
	with open(filename, 'r') as f:
	    for line in f:
	        line = line.strip()
	        if line == '': continue
	        entries.append(line)
	return entries

def configure_switch(file_name, thrift_port):
        entries = read_entries(file_name)
        print '\n'.join(entries)
	p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE)
        p.communicate(input='\n'.join(entries))

if __name__ == "__main__":
        if len(sys.argv) == 3:
		configure_switch(sys.argv[1], sys.argv[2])
        else:
		print "Usage: python filename s1-commands.txt 9090"



# EXAMPLE :
# osboxes@osboxes:~/p4git/tutorials_forked/tutorials/my_exercises/ipv6_examples/ioam$ ./configure_switch_entries.py 
# Usage: python filename s1-commands.txt 9090
# osboxes@osboxes:~/p4git/tutorials_forked/tutorials/my_exercises/ipv6_examples/ioam$ ./configure_switch_entries.py s1-commands.txt 9090
# table_set_default ipv6_lpm drop
# table_set_default ioam_trace add_ioam_trace 1
# table_add ipv6_lpm ipv6_forward 2001::13/96 => 00:aa:00:01:00:01 1
# table_add ipv6_lpm ipv6_forward 3001::13/96 => f2:ed:e6:df:4e:fa 2
# table_add ipv6_lpm ipv6_forward 4001::13/96 => f2:ed:e6:df:4e:fb 3
# Obtaining JSON from switch...
# Done
# Control utility for runtime P4 table manipulation
# RuntimeCmd: Setting default action of ipv6_lpm
# action:              drop
# runtime data:        
# RuntimeCmd: Setting default action of ioam_trace
# action:              add_ioam_trace
# runtime data:        00:00:01
# RuntimeCmd: Adding entry to lpm match table ipv6_lpm
# match key:           LPM-20:01:00:00:00:00:00:00:00:00:00:00:00:00:00:13/96
# action:              ipv6_forward
# runtime data:        00:aa:00:01:00:01	00:01
# Invalid table operation (DUPLICATE_ENTRY)
# RuntimeCmd: Adding entry to lpm match table ipv6_lpm
# match key:           LPM-30:01:00:00:00:00:00:00:00:00:00:00:00:00:00:13/96
# action:              ipv6_forward
# runtime data:        f2:ed:e6:df:4e:fa	00:02
# Invalid table operation (DUPLICATE_ENTRY)
# RuntimeCmd: Adding entry to lpm match table ipv6_lpm
# match key:           LPM-40:01:00:00:00:00:00:00:00:00:00:00:00:00:00:13/96
# action:              ipv6_forward
# runtime data:        f2:ed:e6:df:4e:fb	00:03
# Invalid table operation (DUPLICATE_ENTRY)
# RuntimeCmd: 
# 
