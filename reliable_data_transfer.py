import argparse
import logging

# configuring warning output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as sc

# configuring scapy 
sc.conf.use_pcap = False
sc.conf.iface = sc.get_working_if()

# global variables to set output and timing
VERBOSE = False
PACKET_TIMEOUT = 4
MAX_PACKETS_IN_FLIGHT = 4

ACK_TYPE = 0b1
NACK_TYPE = 0b0

# RDTP layer which includes required header fields
class RDTP(sc.Packet):
    name="Reliable Data Transfer Protocol"
    fields_desc = [
        sc.Intfield("seq_num",0x00000000),
        sc.IntField("ack_num",0x00000000),
        sc.BitField("syn",0b0),
        sc.BitField("ack",0b0),
        sc.BitField("fin",0b0),
        sc.IntField("checksum",0x00000000)
    ]
    
# sc.IntField("src_port",0x00000000),
# sc.IntField("dst_port",0x00000000),

dport = ""
sport = ""
dst_address = "127.0.0.1"

data = "HELLO"

packet = sc.IP(dst=dst_address) / RDTP(seq_num=-1,) / sc.UDP(dport=dport) / data


def send_packet(data, host, port):
            
    # TODO : v replace or wrap new header with ACK and SEQ NUM CHECKSUM data
    
    packet = sc.IP(dst=host) / sc.UDP(dport=port) / data
            
    answered = sc.sr1(packet, verbose=VERBOSE, timeout=PACKET_TIMEOUT)
        
    return answered


def build_header(data, host, port, syn=False, ack=False):

    return     


def receive_packet(packet):
    # decompose packet to see if it is data or ACK, get seq num, get checksum and compute 
    return False


def send_ACK(packet_to_reply_to: sc.packet.Packet, ack_type, seq_num):
    
    if not packet_to_reply_to.haslayer(sc.IP):
        return None
    
    if not packet_to_reply_to.haslayer(sc.UDP):
        return None
    
    dst_address = packet_to_reply_to[sc.IP] # get src address
    dst_port = packet_to_reply_to[sc.UDP] # get src port number
    
    if ack_type == ACK_TYPE:
        # send ACK with seq num and checksum
        print(f"ACK:\t{seq_num}") # revise
        
        # build packet+send
        
    elif ack_type == NACK_TYPE:
        # send NACK with seq num and checksum
        print(f"NACK:\t{seq_num}") # revise
        
        # build packet+send


def validate_checksum(packet: sc.packet.Packet):
    
    packet_checksum = packet.fields["checksum"] # decompose packet to get checksum
    computed_checksum = sc.checksum(packet) # compute checksum
    
    # verify checksum value is equivalent to sum of packets bits 
    if packet_checksum == computed_checksum: 
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
    