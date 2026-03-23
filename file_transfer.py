import argparse
import logging
import os
from reliable_data_transfer import RDTP, RECEIVER_PORT, SENDER_PORT, SIMULATOR_PORT, build_packet, receive_packet, run_sender, send_ack, validate_checksum

# configuring warning output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as sc

# configuring scapy 
sc.conf.use_pcap = True
sc.conf.iface = "\\Device\\NPF_Loopback"
sc.conf.sniff_promisc = False

# global variable to set chunk size
CHUNK_SIZE = 512


def receive_stream(listening_port, start_seq_num=0):
    
    expected_seq_num = start_seq_num
    received_data = {}
    completed = [False]

    def on_packet(packet):
        if not packet.haslayer(sc.UDP) or not packet.haslayer(RDTP):
            return
        
        if packet[sc.UDP].dport != listening_port:
            return
        
        rdtp = packet[RDTP]
        if rdtp.ack == 1:
            return
        
        if rdtp.fin == 1:
            send_ack(packet, rdtp.seq_num)
            completed[0] = True
            return
        
        nonlocal expected_seq_num
        
        expected_seq_num, _ = receive_packet(packet, expected_seq_num, received_data)

    sc.sniff(prn=on_packet, stop_filter=lambda _: completed[0], store=0, iface=sc.conf.iface)
    
    result = b""
    for k in sorted(received_data):
        result += received_data[k]
        
    return result


def client_put(local_path, host, port):
    
    if not os.path.isfile(local_path):
        print(f"ERROR: '{local_path}' not found")
        return
    
    filename = os.path.basename(local_path)
    file_data = open(local_path, "rb").read()
    print(f"PUT '{filename}' ({len(file_data)} bytes) -> {host}:{port}")
    
    command = f"PUT {filename} {len(file_data)}".encode()
    payloads = [command] + [file_data[i:i+CHUNK_SIZE] for i in range(0, len(file_data), CHUNK_SIZE)]
    
    run_sender(payloads, host, port)
    print(f"Upload complete: '{filename}'")


def client_get(remote_filename, local_save_path, host, port):
    
    print(f"GET '{remote_filename}' from {host}:{port} -> '{local_save_path}'")
    sc.send(build_packet(f"GET {remote_filename}".encode(), host, port, seq_num=0, ack_num=0), verbose=False)
    
    sc.bind_layers(sc.UDP, RDTP, dport=SENDER_PORT)
    
    file_bytes = receive_stream(SENDER_PORT)
    open(local_save_path, "wb").write(file_bytes)
    print(f"Saved {len(file_bytes)} bytes -> '{local_save_path}'")


def start_server(listen_port):
    sc.bind_layers(sc.UDP, RDTP, dport=listen_port)
    print(f"FILE TRANSFER SERVER on port {listen_port}")

    while True:
        command_packet = [None]
        # wait for command packet
        def on_cmd(packet):
            if packet.haslayer(sc.UDP) and packet.haslayer(RDTP) and packet[sc.UDP].dport == listen_port:
                
                rdtp = packet[RDTP]
                if rdtp.ack == 0 and rdtp.fin == 0 and validate_checksum(packet):
                    command_packet[0] = packet
        
        sc.sniff(prn=on_cmd, stop_filter=lambda _: command_packet[0] is not None, store=0, iface=sc.conf.iface)

        packet = command_packet[0]
        
        try:
            parts = bytes(packet[RDTP].payload).decode().strip().split()
            cmd, filename = parts[0].upper(), os.path.basename(parts[1])
            
        except Exception:
            print("Unknown command - ignoring")
            continue

        print(f"COMMAND: {cmd} '{filename}'")
        client_ip, client_port = packet[sc.IP].src, packet[sc.UDP].sport

        if cmd == "PUT":
            total_bytes = int(parts[2])
            print(f"PUT '{filename}' - expecting {total_bytes} bytes")
            
            send_ack(packet, 0)
            
            file_bytes = receive_stream(listen_port, start_seq_num=1)
            open(filename, "wb").write(file_bytes)
            print(f"Saved '{filename}' ({len(file_bytes)} bytes)")

        elif cmd == "GET":
            
            if not os.path.isfile(filename):
                print(f"GET ERROR: '{filename}' not found")
                sc.send(build_packet(b"ERROR: not found", client_ip, client_port, seq_num=0, ack_num=0, fin=True), verbose=False)
                
                continue
            
            file_data = open(filename, "rb").read()
            print(f"GET '{filename}' - sending {len(file_data)} bytes")
            
            payloads = []
            for i in range(0, len(file_data), CHUNK_SIZE):
                payloads.append(file_data[i:i+CHUNK_SIZE])
                
            if not payloads:
                payloads = [b""]
            
            run_sender(payloads, client_ip, client_port)
            print(f"GET '{filename}' - complete")


if __name__ == "__main__":
    print("\nRDTP File Transfer\n")
    
    parser = argparse.ArgumentParser(description="File transfer over RDTP")
    
    parser.add_argument("address", 
                        type=str, 
                        help="Server IP address"
                        )
    
    parser.add_argument("port", 
                        type=str, 
                        help="Destination UDP port"
                        )
    
    parser.add_argument("-s", 
                        action="store_true", 
                        help="Run as client"
                        )
    
    parser.add_argument("-r", 
                        action="store_true", 
                        help="Run as server"
                        )
    
    parser.add_argument("--put", 
                        type=str, 
                        metavar="FILE", 
                        help="Upload FILE to server"
                        )
    
    parser.add_argument("--get", 
                        type=str, 
                        metavar="FILE", 
                        help="Download FILE from server"
                        )
    
    parser.add_argument("--out", 
                        type=str, 
                        metavar="OUTFILE", 
                        default=None, 
                        help="Save download as OUTFILE"
                        )

    args = parser.parse_args()
    
    
    target_ip = args.address
    target_port = int(args.port)

    # setup scapy bound layers
    for dport in (target_port, RECEIVER_PORT):
        sc.bind_layers(sc.UDP, RDTP, dport=dport)
        
    for sport in (SENDER_PORT, RECEIVER_PORT, SIMULATOR_PORT):
        sc.bind_layers(sc.UDP, RDTP, sport=sport)

    # process arguments
    if args.r:
        start_server(target_port)
        
    elif args.s:
        if args.put:
            client_put(args.put, target_ip, target_port)
            
        elif args.get:
            client_get(args.get, args.out or args.get, target_ip, target_port)
        
        else:
            parser.print_help()
            
    else:
        parser.print_help()