import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import pyfiglet
import time

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        # Check for protocol type (TCP/UDP)
        protocol = 'TCP' if packet.haslayer(TCP) else 'UDP' if packet.haslayer(UDP) else 'Other'
        print(f"Source IP: {src_ip} -> Destination IP: {dst_ip} | Protocol: {protocol}")
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = packet[protocol].payload
            print(f"Payload Data: {payload}\n")
        else:
            print("No Payload Data\n")

if __name__ == "__main__":
    banner = pyfiglet.figlet_format("PacketSniffer")
    print(banner)
    try :
        print("Starting packet sniffer...")
        scapy.sniff(filter="ip", prn=packet_callback , iface="eth0")
        print("Packet sniffer stopped.")
    except KeyboardInterrupt :
        print("\n[+] Detected CTRL + C ... Please wait !! ")
        time.sleep(2)
        print("Quitting Successfully")
