import argparse
import logging
import socket

# configuring warning output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as sc

# configuring scapy 
sc.conf.use_pcap = False
sc.conf.iface = sc.get_working_if()

VERBOSE = False
PACKET_TIMEOUT = 4
ACK_TYPE = 1
NACK_TYPE = 0

def send_packet(data, host, port):
            
    #       TODO : v should this [IP part] be replaced by the new header with ACK and SEQ NUM CHECKSUM data
    packet = sc.IP(dst=host) / sc.UDP(dport=port) / data
            
    answered = sc.sr1(packet, verbose=VERBOSE, timeout=PACKET_TIMEOUT)
        
    return answered

def send_ACK(ack_type, seq_num, checksum):
    
    if ack_type == ACK_TYPE:
        # send ACK with seq num and checksum
        print(f"ACK:\t{seq_num}") # revise
        
    elif ack_type == NACK_TYPE:
        # send NACK with seq num and checksum
        print(f"NACK:\t{seq_num}") # revise