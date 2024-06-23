from scapy.all import sniff, IP, TCP, UDP, conf

def packet_handler(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"[IP] Source: {ip_layer.src} -> Destination: {ip_layer.dst}")
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"[TCP] Source Port: {tcp_layer.sport} -> Destination Port: {tcp_layer.dport}")
            if tcp_layer.payload:
                try:
                    payload = bytes(tcp_layer.payload).decode('utf-8', errors='replace')
                except Exception as e:
                    payload = str(tcp_layer.payload)
                print(f"[TCP] Payload: {payload}")
        
        if UDP in packet:
            udp_layer = packet[UDP]
            print(f"[UDP] Source Port: {udp_layer.sport} -> Destination Port: {udp_layer.dport}")
            if udp_layer.payload:
                try:
                    payload = bytes(udp_layer.payload).decode('utf-8', errors='replace')
                except Exception as e:
                    payload = str(udp_layer.payload)
                print(f"[UDP] Payload: {payload}")

def main():
    print("Starting packet capture. Press Ctrl+C to stop.")
    conf.use_pcap = True  # Ensure that Scapy uses Npcap/WinPcap
    try:
        sniff(prn=packet_handler, count=10)
    except KeyboardInterrupt:
        print("\nPacket capture stopped.")
    except RuntimeError as e:
        print(f"RuntimeError: {e}")
        print("Ensure Npcap is installed and running correctly.")

if __name__ == "__main__":
    main()
