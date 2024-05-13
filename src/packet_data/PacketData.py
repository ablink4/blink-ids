"""
Encapsulates packet data that is ingested from the network and forwarded to the rules engine.
"""

import time
from datetime import datetime, timezone
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether


class PacketData:
    def __init__(self, packet_id: int, raw_packet: scapy.packet):
        """
        Initializes a new instance of the PacketData class.

        :param packet_id: a unique id for this packet
        :param raw_packet: The raw packet as received on the network
        """
        self.packet_id = packet_id
        self.raw_packet = raw_packet
        self.packet_bytes = bytes(raw_packet)
        self.packet_timestamp = time.time_ns()  # assume packet was received right now - may not be a good assumption
        self.payload = None

        self.ethernet_src = None
        self.ethernet_dst = None

        self.ip_src = None
        self.ip_dst = None
        self.ip_protocol = None
        self.ip_ttl = None

        self.tcp_src_port = None
        self.tcp_dest_port = None
        self.tcp_flags = None
        self.tcp_seq_num = None
        self.tcp_ack_num = None

        self.udp_src_port = None
        self.udp_dest_port = None

        self.icmp_type = None
        self.icmp_code = None

        self._extract_packet_data()

    def __str__(self):
        """
        Return a string representation of the PacketData object.
        """
        output = f"Packet ID: {self.packet_id}\n"

        dt = datetime.fromtimestamp(self.packet_timestamp / 1_000_000_000)
        output += f"Packet Timestamp: {dt.strftime('%Y-%m-%d %H:%M:%S.%f')}\n"

        output += "Ethernet Data:"
        output += f"\tEthernet Source: {self.ethernet_src}\n"
        output += f"\tEthernet Destination: {self.ethernet_dst}\n"

        output += "IP Data:"
        output += f"\tIP Source: {self.ip_src}\n"
        output += f"\tIP Destination: {self.ip_dst}\n"
        output += f"\tIP Protocol: {self.ip_protocol}\n"
        output += f"\tIP TTL: {self.ip_ttl}\n"

        if self.tcp_src_port is not None:
            output += "TCP Data:"
            output += f"\tTCP Source Port: {self.tcp_src_port}\n"
            output += f"\tTCP Destination Port: {self.tcp_dest_port}\n"
            output += f"\tTCP Flags: {self.tcp_flags}\n"
            output += f"\tTCP Sequence Number: {self.tcp_seq_num}\n"
            output += f"\tTCP Acknowledgement Number: {self.tcp_ack_num}\n"
        elif self.udp_src_port is not None:
            output += "UDP Data:"
            output += f"\tUDP Source Port: {self.udp_src_port}\n"
            output += f"\tUDP Destination Port: {self.udp_dest_port}\n"

        if self.icmp_type is not None:
            output += "ICMP Data:"
            output += f"\tICMP Type: {self.icmp_type}\n"
            output += f"\tICMP Code: {self.icmp_code}\n"

        output += f"Packet Payload: {self.payload}\n"
        output += f"Packet Bytes: {self.packet_bytes}\n"

        return output

    def _extract_packet_data(self):
        """
        Extract and parse the various layers of data from the raw packet.
        """

        if self.raw_packet.haslayer(Raw):
            self.payload = self.raw_packet.getlayer(Raw).load

        # Extract Ethernet frame data
        if self.raw_packet.haslayer(Ether):
            self.ethernet_src = self.raw_packet[Ether].src
            self.ethernet_dst = self.raw_packet[Ether].dst

        # Extract IP packet data
        if self.raw_packet.haslayer(IP):
            self.ip_src = self.raw_packet[IP].src
            self.ip_dst = self.raw_packet[IP].dst
            self.ip_protocol = self.raw_packet[IP].proto
            self.ip_ttl = self.raw_packet[IP].ttl

        if self.raw_packet.haslayer(ICMP):
            self.icmp_type = self.raw_packet[ICMP].type
            self.icmp_code = self.raw_packet[ICMP].code

        # Extract transport layer data (TCP or UDP)
        if self.raw_packet.haslayer(TCP):
            self.tcp_src_port = self.raw_packet[TCP].sport
            self.tcp_dest_port = self.raw_packet[TCP].dport
            self.tcp_seq_num = self.raw_packet[TCP].seq
            self.tcp_ack_num = self.raw_packet[TCP].ack
            self.tcp_flags = self.raw_packet[TCP].flags
        elif self.raw_packet.haslayer(UDP):
            self.udp_src_port = self.raw_packet[UDP].sport
            self.udp_dest_port = self.raw_packet[UDP].dport

