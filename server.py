#!/usr/bin/python

import sys
import os
import argparse
import time
import setproctitle
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#apparently this gets most common process names?
# command = os.popen(ps -aux | awk '{ print $11 }' | sort | uniq -c | sort -n | tail -n1 | awk '{ print $2}')
# command_result = command.read()
# print "Most common process for ps/htop: {0} \n".format(command_result)

def authenticate(pkt):
	port = pkt['TCP'].dport
	if port == 2000 and 2001 and 2002:
		print 'ok!'

def main():
	sniff(filter="ip and tcp", prn=authenticate)

main()

