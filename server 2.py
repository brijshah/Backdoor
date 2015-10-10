#!/usr/bin/python

import sys
import os
import argparse
import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

knock = [2000,2001,2002]
count = 0

def createServer(host, port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serverAddr = (host, port)
	sock.bind(serverAddr)

def remoteExecute(pkt):
	global count
	wnd = pkt[2].window
	if wnd == 4096:
		port = pkt[2].sport
		if port == knock[0]:
			count +=1
		if port == knock[1]:
			count +=1
		if port == knock[2]:
			count +=1
		if count == 3:
			#do shit here
	elif count < 3:
		return

def main():
	sniff(filter="ip and tcp", prn=remoteExecute)

main()
