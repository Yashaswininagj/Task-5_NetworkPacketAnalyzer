import scapy.all as scapy

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"[*] {src_ip} --> {dst_ip} Protocol: {protocol}")
        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            print(f"[*] Payload: {payload}")

def main():
    interface = input("Enter the interface to sniff on (e.g., eth0): ")
    print("[*] Sniffing started. Press Ctrl+C to stop.")
    sniff_packets(interface)

if __name__ == "__main__":
    main()

# please install scapy
# ------pip install scapy