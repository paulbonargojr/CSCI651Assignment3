import argparse
import logging

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


def receive_packet(packet):
    # decompose packet to see if it is data or ACK, get seq num, get checksum and compute 
    return False


def send_ACK(ack_type, seq_num, checksum):
    
    if ack_type == ACK_TYPE:
        # send ACK with seq num and checksum
        print(f"ACK:\t{seq_num}") # revise
        
    elif ack_type == NACK_TYPE:
        # send NACK with seq num and checksum
        print(f"NACK:\t{seq_num}") # revise
        

def compute_checksum(packet):
    checksum = decompose(packet) # decompose packet to get checksum
    
    if checksum == len(packet): # see if checksum is len of packet
        return True
    
    return False



if __name__ == "__main__":

    # ingest CLI call args TODO : add description and additional arguments
    parser = argparse.ArgumentParser(description="")

    # Address (positional argument) : Specify address to send packets to
    parser.add_argument("address", 
                        type=str,
                        help="Address to send packet")
    
    # Port (positional argument) : Specify port to send packets through
    parser.add_argument("port", 
                        type=str,
                        help="Port to send packet through")
    
    # timeout (-t) : Specify a timeout in seconds before ping exits regardless of how many packets have been received.
    # None as default
    parser.add_argument("-t",
                        type=int,
                        required=False,
                        help="Seconds until timeout before data transfer terminates"
                        ) # timeout in seconds

    args = parser.parse_args()

    target_ip = args.address
    target_port = args.port
    timeout_seconds = args.t
    