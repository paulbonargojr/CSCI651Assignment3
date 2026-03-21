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
        sc.Intfield("seq_num",0),
        sc.IntField("ack_num",0),
        sc.BitField("syn",0b0,1),
        sc.BitField("ack",0b0,1),
        sc.BitField("fin",0b0,1),
        sc.IntField("padding",0, 5),
        sc.IntField("checksum",0)
    ]
    
# sc.IntField("src_port",0x00000000),
# sc.IntField("dst_port",0x00000000),

# sport = ""
dport = ""
dst_address = "127.0.0.1"

data = "HELLO"

packet = sc.IP(dst=dst_address) / RDTP(seq_num=-1,) / sc.UDP(dport=dport) / data


def compute_checksum(data: bytes):
    """compute the checksum of data

    Args:
        data (bytes): data of packet to check sum of

    Returns:
        int: checksum value
    """
    return sum(data) % (2 ** 32)


def validate_checksum(packet: sc.packet.Packet):
    rdtp = packet[RDTP]
    
    packet_checksum = rdtp.checksum # decompose packet to get checksum field
    computed_checksum = compute_checksum(packet) # compute checksum
    
    return computed_checksum == packet_checksum


def build_packet(data, host, port, seq_num, ack_num, syn=False, ack=False, fin=False):
    
    header = RDTP(seq_num=seq_num, ack_num=ack_num, syn=syn, ack=ack, fin=fin, padding=0, checksum=0)
    raw = bytes(header) + data
    checksum = compute_checksum(raw)

    header.checksum = checksum
    # TODO : FIX THIS v
    header.padding = -1
    
    return sc.IP(dst=host) / sc.UDP(dport=port) / header / data


def send_packet(seq_num, data, host, port):
    
    pkt = build_packet(data, host, port, seq_num, 0)
    sc.send(pkt, verbose=False)
    # TODO : v replace or wrap new header with ACK and SEQ NUM CHECKSUM data
    
    packet = sc.IP(dst=host) / sc.UDP(dport=port) / data
            
    answered = sc.sr1(packet, verbose=VERBOSE, timeout=PACKET_TIMEOUT)
        
    return answered


def send_ACK(packet_to_reply_to: sc.packet.Packet, seq_num):
    
    if not packet_to_reply_to.haslayer(sc.IP) or not packet_to_reply_to.haslayer(sc.UDP):
        return None
    
    # send ACK with seq num and checksum
    print(f"ACK:\t{seq_num}")
        
    # build packet+send
    dst_address = packet_to_reply_to[sc.IP].src # get src address
    dst_port = packet_to_reply_to[sc.UDP].sport # get src port number
    
    rdtp = RDTP(seq_num=0, ack_num=seq_num, ack=1, checksum=0)
    
    ack_packet = sc.IP(dst=dst_address) / sc.UDP(dport=dst_port) / rdtp

    data = bytes(ack_packet[RDTP])
    ack_packet[RDTP].checksum = compute_checksum(data)

    sc.send(ack_packet, verbose=False)



def receive_packet(packet, expected_seq_num, received_data) -> tuple[int, bin]:
    # decompose packet to see if it is data or ACK, get seq num, get checksum and compute 

    if not packet.haslayer(RDTP):
        return expected_seq_num, 0

    rdtp = packet[RDTP]

    # check checksum
    if not validate_checksum(packet):
        print(f"[DROP]\t\tseq={rdtp.seq_num}")
        return expected_seq_num, 0

    # send ACK
    if rdtp.seq == expected_seq_num:
        print(f"[RECEIVED]\tseq_num={rdtp.seq_num}")
        
        received_data[rdtp.seq_num] = bytes(rdtp.payload)
        
        send_ACK(rdtp.seq_num, packet)
        expected_seq_num += 1

    # resend last ACK
    else:
        print(f"[OUT OF ORDER]: \n\texpected seq_num = {expected_seq_num}\n\treceived seq_num = {rdtp.seq_num}")
        send_ACK(seq_num=expected_seq_num-1, packet_to_reply_to=packet)  
    
    return expected_seq_num, 1



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
    