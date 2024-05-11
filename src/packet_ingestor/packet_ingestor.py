"""
Packet ingestor module for blink-ids.  Responsible for ingesting packets from the network, pulling packet data
relevant to analysis, and forwarding to the rules engine module.
"""

import argparse
from scapy.all import *
from src.packet_data.PacketData import PacketData

packet_id = 0


def get_next_packet_id():
    global packet_id
    packet_id += 1
    return packet_id


def process_packet(pkt: scapy.packet):
    data = PacketData(get_next_packet_id(), pkt)
    print(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", help="Name of the network interface to ingest packets from.  \
    Leave blank to ingest from all interfaces.")

    args = parser.parse_args()

    if args.interface:
        capture = sniff(iface=args.interface, prn=lambda x: process_packet(x))
    else:
        capture = sniff(prn=lambda x: process_packet(x))
