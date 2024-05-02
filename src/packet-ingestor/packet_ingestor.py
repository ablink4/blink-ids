import argparse
from scapy.all import *

packet_id = 0


def print_raw_packet(pkt):
    global packet_id

    print(f'{packet_id}:: {bytes(pkt)}')
    packet_id += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", help="Name of the network interface to ingest packets from.  \
    Leave blank to ingest from all interfaces.")

    args = parser.parse_args()

    if args.interface:
        capture = sniff(iface=args.interface, prn=lambda x: print_raw_packet(x))
    else:
        capture = sniff(prn=lambda x: print_raw_packet(x))

