import argparse
import logging
import time

# configuring warning output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as sc

# configuring scapy 
sc.conf.use_pcap = True

# sc.conf.iface = "Npcap Loopback Adapter"
# sc.conf.iface = sc.get_working_if()
sc.conf.iface = "\\Device\\NPF_Loopback"

sc.conf.sniff_promisc = False

# global variables to set output and timing
VERBOSE = True
PACKET_TIMEOUT = 4
MAX_PACKETS_IN_FLIGHT = 4

ACK_TYPE = 0b1
NACK_TYPE = 0b0

# RDTP layer which includes required header fields
class RDTP(sc.Packet):
    name="Reliable Data Transfer Protocol"
    fields_desc = [
        sc.IntField("seq_num",0),
        sc.IntField("ack_num",0),
        sc.BitField("syn",0b0,1),
        sc.BitField("ack",0b0,1),
        sc.BitField("fin",0b0,1),
        sc.BitField("padding",0, 5),
        sc.IntField("checksum",0)
    ]
    

    
# sc.IntField("src_port",0x00000000),
# sc.IntField("dst_port",0x00000000),

# sport = ""
# dport = ""
# dst_address = "127.0.0.1"

# data = "HELLO"

# packet = sc.IP(dst=dst_address) / RDTP(seq_num=-1,) / sc.UDP(dport=dport) / data


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
    
    copy = rdtp.copy()
    copy.checksum = 0 # set checksum to 0 to check correct sum
    
    computed_checksum = compute_checksum(bytes(copy)) # compute checksum from header and data
    
    return computed_checksum == packet_checksum


def build_packet(data, host, port, seq_num, ack_num, syn=False, ack=False, fin=False):
    
    # convert data to bytes
    if isinstance(data, str):
        data = data.encode()
        
    header = RDTP(seq_num=seq_num, ack_num=ack_num, syn=syn, ack=ack, fin=fin, checksum=0)
    checksum_value = compute_checksum(bytes(header) + data)

    header.checksum = checksum_value
    
    return sc.IP(dst=host) / sc.UDP(sport=12345, dport=int(port)) / header / data


def send_packet(seq_num, data, host, port):
    
    packet = build_packet(data, host, port, seq_num, 0)
    
    if VERBOSE:
        print(f"SEND PACKET {seq_num}")
        
    sc.send(packet, verbose=False)
    # sc.send(packet, iface=sc.conf.iface, verbose=False)
    return packet
    # sc.sendp(pkt, verbose=VERBOSE)
    


def send_ACK(packet_to_reply_to: sc.packet.Packet, seq_num):
    
    if not packet_to_reply_to.haslayer(sc.IP) or not packet_to_reply_to.haslayer(sc.UDP):
        if VERBOSE:
            print(f"ERROR: MISSING LAYERS {seq_num}")
        return None
        
    # build packet+send
    dst_address = packet_to_reply_to[sc.IP].src # get src address
    dst_port = packet_to_reply_to[sc.UDP].sport # get src port number
    
    rdtp_header = RDTP(seq_num=0, ack_num=seq_num, ack=1, checksum=0)
    
    header_bytes = bytes(rdtp_header)
    rdtp_header.checksum = compute_checksum(header_bytes)
    
    # ack_packet = sc.IP(dst=dst_address) / sc.UDP(sport=int(target_port),dport=12345) / rdtp_header
    ack_packet = sc.IP(dst=dst_address) / sc.UDP(sport=dst_port,dport=12345) / rdtp_header

    if VERBOSE:
        print(f"SEND ACK {seq_num}")
    
    sc.send(ack_packet, verbose=False)



def receive_packet(packet, expected_seq_num, received_data) -> tuple[int, bin]:
    # decompose packet to see if it is data or ACK, get seq num, get checksum and compute 

    if not packet.haslayer(RDTP):
        return expected_seq_num, 0

    rdtp = packet[RDTP]
    
    # ignore ACKS
    if rdtp.ack == 1:
        return expected_seq_num, 0

    # check checksum
    if not validate_checksum(packet):
        print(f"DROP\t\tseq={rdtp.seq_num}")
        return expected_seq_num, 0

    # send ACK
    if rdtp.seq_num == expected_seq_num:
        if VERBOSE:
            print(f"RECEIVED\tseq_num={rdtp.seq_num}")
        
        received_data[rdtp.seq_num] = bytes(rdtp.payload)
        
        send_ACK(packet, rdtp.seq_num)
        expected_seq_num += 1

    # resend last ACK
    else:
        print(f"OUT OF ORDER:\n\texpected seq_num = {expected_seq_num}\n\treceived seq_num = {rdtp.seq_num}")
        send_ACK(packet, max(expected_seq_num-1,0))  
    
    return expected_seq_num, 1


def start_receiver():
    
    expected_seq_num = 0
    received_data = {}
    
    def receiver(packet):
        print("p",end=" ") # TODO : REMOVE
        # skip all packets not looking for
        if not packet.haslayer(sc.UDP):
            return

        udp = packet[sc.UDP]

        if udp.dport != int(target_port) and udp.sport != 12345:
            return

        if not packet.haslayer(RDTP):
            return
        
        if VERBOSE:
            print("RECEIVED PACKET:", packet.summary())
        
        nonlocal expected_seq_num
        expected_seq_num, result = receive_packet(packet,expected_seq_num, received_data)

    print("START RECEIVER")
    
    sc.sniff(prn=receiver, store=0, iface=sc.conf.iface)
    # sc.sniff(filter=f"udp port {target_port}", prn=receiver, store=0, iface=sc.conf.iface)
    # sc.sniff(prn=receiver, store=0, iface=sc.conf.iface)

def test_sender(host, port):
    messages = [b"Hello", b"World", b"!!!!!", b"THIS IS A TEST", b"I HOPE YOU PASS"]
    seq_num_next = 0
    window_start = 0
    flight_times = {}
    not_acked_packets = {}
    acks_received = set()
    
    max_length = len(messages)
    
    def ack_sniff(packet):
        # ignore packets without RDTP layer present
        if not packet.haslayer(RDTP) or not packet.haslayer(sc.UDP):
            return

        udp = packet[sc.UDP]
        rdtp = packet[RDTP]
        
        if udp.dport != 12345:
            return
                
        if rdtp.ack != 1:
            return

        seq_num = rdtp.ack_num
        if seq_num in acks_received:
            return
        acks_received.add(seq_num)
        
        if seq_num in not_acked_packets:
            if VERBOSE:
                print(f"RECEIVED ACK\tseq_num={seq_num}")
            del not_acked_packets[seq_num]
            
            nonlocal window_start
            
            while window_start < max_length and window_start not in not_acked_packets:
                window_start += 1
        
    sniffer = sc.AsyncSniffer(filter=f"udp", prn=ack_sniff, store=False, iface=sc.conf.iface)
    sniffer.start()
    
    while window_start < max_length:
        
        # in send window
        while seq_num_next < window_start + MAX_PACKETS_IN_FLIGHT and seq_num_next < max_length:
            packet_sent = send_packet(seq_num_next ,messages[seq_num_next], host, port)
            if VERBOSE:
                print(f"SEND\tseq_num={seq_num_next}")
            flight_times[seq_num_next] = time.time()
            not_acked_packets[seq_num_next] = packet_sent
            seq_num_next += 1
        time.sleep(0.1)
        
        # wait for all ACKs to be received, go until window start is ACKed
        # while window_start in not_acked_packets:
            # sc.sniff(filter=f"udp and port {target_port}", prn=ack_sniff, timeout=0.5, store=0, iface=sc.conf.iface)
        
        
        current = time.time()
        # retransmit any non-acked packets
        for a_seq_num, a_packet in list(not_acked_packets.items()):
            if current - flight_times[a_seq_num] > PACKET_TIMEOUT:
                sc.send(a_packet, verbose=False)
                flight_times[a_seq_num] = current
                if VERBOSE:
                    print(f"RETRANSMIT PACKET\tseq_num={a_seq_num}")
    
    sniffer.stop()

if __name__ == "__main__":
    # sc.sniff(count=5, prn=lambda p: print(p.summary()), iface=sc.conf.iface)
    
    print("\nCONTINUING...\n")
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
    
    # sender mode (-s) : Specifies a sender mode of operation
    parser.add_argument("-s",
                        required=False,
                        action="store_true",
                        help="Specifies sender mode"
                        )
    
    # receiver mode (-r) : Specifies a receiver mode of operation
    parser.add_argument("-r",
                        required=False,
                        action="store_true",
                        help="Specifies receiver mode"
                        )

    args = parser.parse_args()

    target_ip = args.address
    target_port = args.port
    timeout_seconds = args.t
    sender = args.s
    receiver = args.r
    
    sc.bind_layers(sc.UDP, RDTP, dport=int(target_port))
    sc.bind_layers(sc.UDP, RDTP, sport=12345)
    
    if receiver:
        start_receiver()
    elif sender:
        test_sender(target_ip, target_port)