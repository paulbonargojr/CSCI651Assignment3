import random
import scapy.all as sc
from reliable_data_transfer import RDTP

LOSS_PROBABILITY = 0.2
CORRUPTION_PROBABILITY = 0.1
REORDERING_PROBABILITY = 0.1

SIM_PORT = 12000
RECEIVER_PORT = 12346
SENDER_PORT = 12345

buffer = []

    
def corrupt_packet_chance(packet):
    if random.random() < CORRUPTION_PROBABILITY:
        pkt = packet.copy()

        if pkt.haslayer(sc.Raw):
            payload = bytearray(pkt[sc.Raw].load)
            payload[0] ^= 0xFF  # flip first byte
            pkt[sc.Raw].load = bytes(payload)

        print(f"SIMULATION: CORRUPT seq={pkt[RDTP].seq_num}")
        return pkt

    return packet


def rewrite_ports(packet):
    a_packet = packet.copy()

    # From sender to receiver
    if a_packet[sc.UDP].dport == SIM_PORT and a_packet[sc.UDP].sport == SENDER_PORT:
        a_packet[sc.UDP].dport = RECEIVER_PORT

    # From receiver to sender
    elif a_packet[sc.UDP].dport == SIM_PORT and a_packet[sc.UDP].sport == RECEIVER_PORT:
        a_packet[sc.UDP].dport = SENDER_PORT

    else:
        return None

    return a_packet


def network_forwarding(packet):
    print(packet.summary())
    
    global buffer
    
    if not packet.haslayer(RDTP) or not packet.haslayer(sc.UDP):
        return
    
    rdtp = packet[RDTP]
    print(f"SIMULATION: seq={rdtp.seq_num} ack={rdtp.ack}")

    # loss phase
    if random.random() < LOSS_PROBABILITY:
        print(f"SIMULATION: DROP seq={rdtp.seq_num}")
        return

    # corruption phase
    packet = corrupt_packet_chance(packet)

    # reordering phase
    if random.random() < REORDERING_PROBABILITY:
        print(f"SIMULATION: BUFFER seq={rdtp.seq_num}")
        buffer.append(packet)
        return

    # buffer packets sending  
    while buffer:
        a_packet = buffer.pop(0)
        a_packet = rewrite_ports(a_packet)
        if a_packet is not None:
            a_packet[sc.UDP].sport = SIM_PORT
            sc.send(a_packet, verbose=False)

    # normal sending
    packet = rewrite_ports(packet)
    if packet is None:
        return
    print(f"SUMULATION - forward: dport={packet[sc.UDP].dport}")
    sc.send(packet, verbose=False)
    

def main():
    
    print("NETWORK SIMULATOR")
    print("-----------------")
    sc.bind_layers(sc.UDP, RDTP, dport=SIM_PORT)
    sc.bind_layers(sc.UDP, RDTP, sport=SIM_PORT)
    sc.sniff(prn=network_forwarding, store=0)

if __name__ == "__main__":
    main()
    
    