import random
import scapy.all as sc
from reliable_data_transfer import RDTP
import socket
import traceback

LOSS_PROBABILITY = 0.2
CORRUPTION_PROBABILITY = 0.1
REORDERING_PROBABILITY = 0.1

SIMULATOR_PORT = 12000
RECEIVER_PORT = 12346
SENDER_PORT = 12345

buffer = []

    
def corrupt_packet_chance(packet):
    """random chance to corrupt a packet

    Args:
        packet (scapy.packet.Packet): packet to possibly corrupt

    Returns:
        scapy.packet.Packet: normal or corrupted packet
    """
    if random.random() < CORRUPTION_PROBABILITY:

        raw = bytearray(bytes(packet))
        
        rdtp_offset = 41
        # corruption event: flip byte   
        if len(raw) > rdtp_offset:
            raw[rdtp_offset] ^= 0xFF
        # no payload, flip data in checksum
        else:
            raw[37] ^= 0xFF
            
        a_packet = sc.IP(bytes(raw))

        print(f"SIMULATION: CORRUPT seq={a_packet[RDTP].seq_num}")
        return a_packet
    return packet


def rewrite_ports(packet):
    """changes ports of a copy of a passed packet to simulate a network

    Args:
        packet (scpy.packet.Packets): packet to forward

    Returns:
        scapy.packet.Packet: packet with ports switched
    """
    a_packet = packet.copy()
    sport = a_packet[sc.UDP].sport
    dport = a_packet[sc.UDP].dport

    # sender to receiver
    if dport == SIMULATOR_PORT and sport == SENDER_PORT:
        a_packet[sc.UDP].dport = RECEIVER_PORT

    # receiver to sender
    elif dport == SIMULATOR_PORT and sport == RECEIVER_PORT:
        a_packet[sc.UDP].dport = SENDER_PORT

    else:
        return None
    
    a_packet[sc.UDP].sport = SIMULATOR_PORT
    
    del a_packet[sc.IP].chksum
    del a_packet[sc.UDP].chksum

    return a_packet


def forward(packet):
    """forward packet using sockets 

    Args:
        packet (scapy.packet.Packet): packet to send
    """
    payload = bytes(packet[sc.UDP].payload)
    
    a_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    
    a_socket.sendto(payload, (packet[sc.IP].dst, packet[sc.UDP].dport))

    a_socket.close()


def network_forwarding(packet):
    """sends packets from sender to receiver, taking into account
    any loss, reordering, or corruption

    Args:
        packet (scapy.packet.Packet): packet to send
    """
    print(packet.summary())
    
    try:
        global buffer
        
        if not packet.haslayer(RDTP) or not packet.haslayer(sc.UDP):
            return
        
        udp = packet[sc.UDP]
        if udp.sport == SIMULATOR_PORT:
            return 
        
        rdtp = packet[RDTP]
        print(f"SIMULATION: seq={rdtp.seq_num} ack={rdtp.ack}")
        
        # always forward FIN so receiver exits
        if rdtp.fin == 1:
            forward_packet = rewrite_ports(packet)
            if forward_packet is not None:
                forward(forward_packet)
            return

        # loss phase
        if random.random() < LOSS_PROBABILITY:
            print(f"SIMULATION: DROP seq={rdtp.seq_num}")
            return

        # reordering phase
        if random.random() < REORDERING_PROBABILITY:
            print(f"SIMULATION: BUFFER seq={rdtp.seq_num}")
            buffer.append(packet)
            return

        # buffer packets sending  
        while buffer:
            a_packet = buffer.pop(0)
            forwarding_packet = rewrite_ports(a_packet)
            if forwarding_packet is not None:
                # corruption phase
                forwarding_packet = corrupt_packet_chance(forwarding_packet)
                
                print(f"SIMULATION: BUFFERED seq_num={a_packet[RDTP].seq_num}")
                forward(forwarding_packet)
                # sc.send(forwarding_packet, verbose=False)
                # sc.sendp(sc.Ether()/forwarding_packet, verbose=False)

        # normal sending
        forward_packet = rewrite_ports(packet)
        if forward_packet is None:
            print("SIMULATION: DROP")
            return 
        
        forward_packet = corrupt_packet_chance(forward_packet)
        
        if forward_packet is None:
            print(f"SIMULATION: DROP")
            return
        
        print(f"SIMULATION: FORWARD seq_num={rdtp.seq_num} dport={forward_packet[sc.UDP].dport}")
        forward(forward_packet)
        # sc.send(forward_packet, verbose=False)
        # sc.sendp(sc.Ether()/forward_packet, verbose=False)
    except Exception as e:
        print(f"SIMULATION: ERROR - {e}")
        traceback.print_exc()

def main():
    
    print("NETWORK SIMULATOR")
    print(f"LOSS PROBABILITY       \t: {LOSS_PROBABILITY*100:.2f}%")
    print(f"CORRUPTION PROBABILITY \t: {CORRUPTION_PROBABILITY*100:.2f}%")
    print(f"REORDER PROBABILITY    \t: {REORDERING_PROBABILITY*100:.2f}%")
    print("-----------------------------------------------------")
    
    sc.bind_layers(sc.UDP, RDTP, dport=SIMULATOR_PORT)
    sc.bind_layers(sc.UDP, RDTP, sport=SIMULATOR_PORT)
    
    sc.sniff(filter="udp", prn=network_forwarding, store=0)

if __name__ == "__main__":
    main()
    
    