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
