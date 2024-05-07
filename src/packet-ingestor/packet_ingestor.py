import argparse
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

packet_id = 0


def print_raw_packet(pkt: scapy.packet):
    global packet_id

    print(f'{packet_id}:: {bytes(pkt)}')
    packet_id += 1


def print_packet_type(pkt: scapy.packet):
    if pkt.haslayer("ICMP"):
        print("ICMP")

    if pkt.haslayer("IP"):
        src_ip = pkt["IP"].src
        dst_ip = pkt["IP"].dst

        print(f"IP, source: {src_ip}, destination: {dst_ip}")

        if pkt.haslayer("TCP"):
            print("TCP")

        if pkt.haslayer("UDP"):
            print("UDP")


def print_packet_data(pkt: scapy.packet):
    # Extract data from the Ethernet layer
    if pkt.haslayer(Ether):
        ether_src = pkt[Ether].src
        ether_dst = pkt[Ether].dst
        print(f"Ethernet Source: {ether_src}")
        print(f"Ethernet Destination: {ether_dst}")

    # Extract data from the IP layer
    if pkt.haslayer(IP):
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        ip_ttl = pkt[IP].ttl
        print(f"IP Source: {ip_src}")
        print(f"IP Destination: {ip_dst}")
        print(f"IP TTL: {ip_ttl}")

    # Extract data from the TCP layer
    if pkt.haslayer(TCP):
        tcp_sport = pkt[TCP].sport
        tcp_dport = pkt[TCP].dport
        tcp_seq = pkt[TCP].seq
        tcp_ack = pkt[TCP].ack
        print(f"TCP Source Port: {tcp_sport}")
        print(f"TCP Destination Port: {tcp_dport}")
        print(f"TCP Sequence Number: {tcp_seq}")
        print(f"TCP Acknowledgment Number: {tcp_ack}")

    # Extract data from the UDP layer
    if pkt.haslayer(UDP):
        udp_sport = pkt[UDP].sport
        udp_dport = pkt[UDP].dport
        print(f"UDP Source Port: {udp_sport}")
        print(f"UDP Destination Port: {udp_dport}")

    # Extract data from the ICMP layer
    if pkt.haslayer(ICMP):
        icmp_type = pkt[ICMP].type
        icmp_code = pkt[ICMP].code
        print(f"ICMP Type: {icmp_type}")
        print(f"ICMP Code: {icmp_code}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", help="Name of the network interface to ingest packets from.  \
    Leave blank to ingest from all interfaces.")

    args = parser.parse_args()

    if args.interface:
        capture = sniff(iface=args.interface, prn=lambda x: print_packet_data(x))
    else:
        capture = sniff(prn=lambda x: print_packet_data(x))
