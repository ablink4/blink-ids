"""
Encapsulates packet data that is ingested from the network and forwarded to the rules engine.
"""

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
        self.ethernet_src = None
        self.ethernet_dst = None
        self.ip_src = None
        self.ip_dst = None
        self.ip_protocol = None
        self.tcp_src_port = None
        self.tcp_dest_port = None
        self.udp_src_port = None
        self.udp_dest_port = None
        self.icmp_type = None
        self.icmp_code = None
        self.ip_ttl = None
        self.tcp_seq = None
        self.tcp_ack = None

        # TODO: add these (or remove, if unneeded)
        self.packet_direction = None
        self.packet_timestamp = None
        self.packet_flags = None
        self.packet_checksum = None
        self.packet_window = None
        self.packet_urgent = None
        self.packet_options = None

        self._extract_packet_data()

    def __str__(self):
        """
        Return a string representation of the PacketData object.
        """
        output = f"Packet ID: {self.packet_id}\n"
        output += f"Ethernet Source: {self.ethernet_src}\n"
        output += f"Ethernet Destination: {self.ethernet_dst}\n"
        output += f"IP Source: {self.ip_src}\n"
        output += f"IP Destination: {self.ip_dst}\n"
        output += f"IP Protocol: {self.ip_protocol}\n"

        if self.tcp_src_port is not None:
            output += f"TCP Source Port: {self.tcp_src_port}\n"
            output += f"TCP Destination Port: {self.tcp_dest_port}\n"
        elif self.udp_src_port is not None:
            output += f"UDP Source Port: {self.udp_src_port}\n"
            output += f"UDP Destination Port: {self.udp_dest_port}\n"

        output += f"Packet Direction: {self.packet_direction}\n"
        output += f"Packet Urgent: {self.packet_urgent}\n"

        output += f"Packet Bytes: {self.packet_bytes}\n"

        return output

    def _extract_packet_data(self):
        """
        Extract and parse the various layers of data from the raw packet.
        """
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
            self.tcp_seq = self.raw_packet[TCP].seq
            self.tcp_ack = self.raw_packet[TCP].ack
        elif self.raw_packet.haslayer(UDP):
            self.udp_src_port = self.raw_packet[UDP].sport
            self.udp_dest_port = self.raw_packet[UDP].dport

