import argparse
import logging
import time

# configuring warning output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as sc

# configuring scapy 
sc.conf.use_pcap = True
sc.conf.iface = "\\Device\\NPF_Loopback"
sc.conf.sniff_promisc = False

# global variables to set output and timing and ports
VERBOSE = True
PACKET_TIMEOUT = 4
MAX_PACKETS_IN_FLIGHT = 4

SIMULATOR_PORT = 12000
RECEIVER_PORT = 12346
SENDER_PORT = 12345

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
    

def compute_checksum(data: bytes):
    """compute the checksum of data

    Args:
        data (bytes): data of packet to check sum of

    Returns:
        int: checksum value
    """
    return sum(data) % (2 ** 32)


def validate_checksum(packet: sc.packet.Packet):
    """verify rdtp checksum is correct from comparing the field
    versus the computed checksum

    Args:
        packet (sc.packet.Packet): packet with an rdtp layer

    Returns:
        bool: if computed checksum matches checksum field
    """
    rdtp = packet[RDTP]
    packet_checksum = rdtp.checksum # decompose packet to get checksum field
    
    copy = rdtp.copy()
    copy.checksum = 0 # set checksum to 0 to check correct sum
    
    computed_checksum = compute_checksum(bytes(copy)) # compute checksum from header and data
    
    return computed_checksum == packet_checksum


def build_packet(data, host, port, seq_num, ack_num, syn=False, ack=False, fin=False):
    """construct a complete IP / UDP / RDTP packet

    Args:
        data (str or bytes): payload of packet to send
        host (str): destination ip address
        port (int or str): destination port number
        seq_num (int): sequence number 
        ack_num (int): acknowledgement number
        syn (bool, optional): flags SYN. Defaults to False.
        ack (bool, optional): flags ACK. Defaults to False.
        fin (bool, optional): flags FIN. Defaults to False.

    Returns:
        scapy.packet.Packet: fully assembled packet to be sent
    """
    # convert data to bytes
    if isinstance(data, str):
        data = data.encode()
        
    header = RDTP(seq_num=seq_num, ack_num=ack_num, syn=int(syn), ack=int(ack), fin=int(fin), checksum=0)
    checksum_value = compute_checksum(bytes(header) + data)

    header.checksum = checksum_value
    
    return sc.IP(dst=host) / sc.UDP(sport=SENDER_PORT, dport=int(port)) / header / data


def send_packet(seq_num, data, host, port):
    """build and transmit a single RDTP packet

    Args:
        seq_num (int): sequence number for this packet
        data (str or bytes): payload
        host (str): destination IP address
        port (int or str): destination UDP port

    Returns:
        scapy.packet.Packet: packet that was sent
    """
    
    packet = build_packet(data, host, port, seq_num, 0)
    
    if VERBOSE:
        print(f"SEND PACKET {seq_num}")
        
    sc.send(packet, verbose=False)
    return packet



def send_ack(packet_to_reply_to: sc.packet.Packet, seq_num):
    """send an ACK packet to sender in response to data packet

    Args:
        packet_to_reply_to (sc.packet.Packet): packet being ACKed
        seq_num (int): sequence number being ACKed
    """
    
    if not packet_to_reply_to.haslayer(sc.IP) or not packet_to_reply_to.haslayer(sc.UDP):
        if VERBOSE:
            print(f"ERROR: MISSING LAYERS {seq_num}")
        return 
        
    # build packet+send
    dst_address = packet_to_reply_to[sc.IP].src # get src address
    dst_port = SENDER_PORT
    # dst_port = packet_to_reply_to[sc.UDP].sport # get src port number
    
    rdtp_header = RDTP(seq_num=0, ack_num=seq_num, ack=1, checksum=0)
    header_bytes = bytes(rdtp_header)
    rdtp_header.checksum = compute_checksum(header_bytes)
    
    print(f"[ACK SEND] port={SIMULATOR_PORT}")    
    ack_packet = sc.IP(dst=dst_address) / sc.UDP(sport=RECEIVER_PORT, dport=dst_port) / rdtp_header

    if VERBOSE:
        print(f"SEND ACK {seq_num}")
    
    sc.send(ack_packet, verbose=False)


def receive_packet(packet, expected_seq_num, received_data) -> tuple[int, bin]:
    """decompose packet to see if it is data or ACK, get seq num, get checksum and compute 

    Args:
        packet (scapy.packet.Packet): scapy packet captured by sniffer
        expected_seq_num (int): next sequence number
        received_data (dict): sequence number : payload bytes

    Returns:
        tuple[int, bin]: new expected sequence number , [1 on successful, 0 on fail]
    """

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
        
        send_ack(packet, rdtp.seq_num)
        return expected_seq_num + 1, 1

    # resend last ACK
    print(f"OUT OF ORDER:\n\texpected seq_num = {expected_seq_num}\n\treceived seq_num = {rdtp.seq_num}")
    send_ack(packet, max(expected_seq_num-1,0))  
    
    return expected_seq_num, 0


def start_receiver(target_port):
    """start RDTP receiver and sniff until a FIN packet is received

    Args:
        target_port (int or str): UDP port to listen on

    Returns:
        dict: sequence number : payload bytes
    """
    
    expected_seq_num = 0
    received_data = {}
    stop_sniff = [False]
    
    target_port = int(target_port)
    
    sc.bind_layers(sc.UDP, RDTP, dport=target_port)
    
    def receiver(packet):
        # skip all packets not looking for
        if not packet.haslayer(sc.UDP):
            return

        udp = packet[sc.UDP]
        if udp.dport != target_port:
            return

        if not packet.haslayer(RDTP):
            return
        
        if VERBOSE:
            print("RECEIVED PACKET:", packet.summary())
            
        rdtp = packet[RDTP]
        
        # handling diconnection, fin bit
        if rdtp.fin == 1:
            print("RECEIVED FIN: closing receiver")
            send_ack(packet, rdtp.seq_num)
            stop_sniff[0] = True
            return
        
        nonlocal expected_seq_num
        expected_seq_num, result = receive_packet(packet, expected_seq_num, received_data)
    
    def stop_filter(b_packet):
        return stop_sniff[0]
    
    print(f"START RECEIVER\nPORT: {target_port}\n")
    
    sc.sniff(prn=receiver, stop_filter=stop_filter, store=0, iface=sc.conf.iface)

    return received_data


def run_sender(messages, host, port):
    """send list of byte payloads using sliding window

    Args:
        messages (list): ordered list of bytes payloads
        host (str): destination ip address
        port (int or str): destination udp port
    """
    seq_num_next = 0
    window_start = 0
    flight_times = {}
    not_acked_packets = {}
    acks_received = set()
    
    max_length = len(messages)

    sc.bind_layers(sc.UDP, RDTP, sport=SIMULATOR_PORT)
    sc.bind_layers(sc.UDP, RDTP, dport=SENDER_PORT)

    def ack_sniff(packet):
        """asyncronous sniffer callback that processes incoming ACKs

        Args:
            packet (scapy.packet.Packet): packet captured by sniffer
        """
        # ignore packets without RDTP layer present
        if not packet.haslayer(RDTP) or not packet.haslayer(sc.UDP):
            return

        udp = packet[sc.UDP]
        rdtp = packet[RDTP]
        
        if udp.dport != SENDER_PORT:
            return
                
        if rdtp.ack != 1:
            return

        seq_num = rdtp.ack_num
        
        print(f"[ACK RECV] seq_num={seq_num}")
        
        if seq_num in acks_received:
            return
        acks_received.add(seq_num)
        
        if seq_num in not_acked_packets:
            if VERBOSE:
                print(f"RECEIVED ACK\tseq_num={seq_num}")
            del not_acked_packets[seq_num]
            
            nonlocal window_start
            
            while window_start < max_length and window_start not in not_acked_packets and window_start in acks_received:
                window_start += 1
        
    sniffer = sc.AsyncSniffer(filter="udp", prn=ack_sniff, store=False, iface=sc.conf.iface)
    sniffer.start()
    
    try:
        
        while window_start < max_length:
            
            # in send window
            while seq_num_next < window_start + MAX_PACKETS_IN_FLIGHT and seq_num_next < max_length:
                packet_sent = send_packet(seq_num_next, messages[seq_num_next], host, port)
                # if VERBOSE:
                #     print(f"SEND\tseq_num={seq_num_next}")
                flight_times[seq_num_next] = time.time()
                not_acked_packets[seq_num_next] = packet_sent
                seq_num_next += 1
                
            time.sleep(0.2)
            
            
            current = time.time()
            # retransmit any non-acked packets
            for a_seq_num, a_packet in list(not_acked_packets.items()):
                if current - flight_times[a_seq_num] > PACKET_TIMEOUT:
                    sc.send(a_packet, verbose=False)
                    flight_times[a_seq_num] = current
                    if VERBOSE:
                        print(f"RETRANSMIT PACKET\tseq_num={a_seq_num}")
    finally:
        sniffer.stop()
        
    # send fin packet to end transfer
    fin_packet = build_packet(b"", host, port, seq_num_next, 0, fin=True)
    sc.send(fin_packet, verbose=False)
    print("FIN SENT: complete")

def test_sender(host, port):
    """send a set of test strings to verify end-to-end functionality

    Args:
        host (str): destination IP address
        port (int or str): destination UDP port
    """
    messages = [b"Hello", b"World", b"!!!!!", b"THIS IS A TEST", b"I HOPE YOU PASS"]
    run_sender(messages, host, int(port))


if __name__ == "__main__":
    # testing here
    # sc.sniff(count=5, prn=lambda p: print(p.summary()), iface=sc.conf.iface)
    
    print("\nReliable Data Transfer Protocol (RDTP)\n")
    parser = argparse.ArgumentParser(description="RDTP sender and receiver")

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
    sc.bind_layers(sc.UDP, RDTP, dport=RECEIVER_PORT)
    
    sc.bind_layers(sc.UDP, RDTP, sport=SENDER_PORT)
    sc.bind_layers(sc.UDP, RDTP, sport=RECEIVER_PORT)
    sc.bind_layers(sc.UDP, RDTP, sport=SIMULATOR_PORT)
    
    if receiver:
        start_receiver(target_port)
    elif sender:
        test_sender(target_ip, target_port)