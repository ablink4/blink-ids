from scapy.all import sniff
"""
Packet ingestor module for blink-ids.  Responsible for ingesting packets from the network, pulling packet data
relevant to analysis, and forwarding to the rules engine module.
"""

from scapy.all import *
from src.packet_data.PacketData import PacketData

from src.packet_queue.PacketQueue import PacketQueue


class PacketIngestor():

    def __init__(self, queue: PacketQueue, interface: str = ""):
        self.interface = interface
        self.queue = queue
        self.packet_id = 0

    def start(self):
        if self.interface != "":
            sniff(iface=self.interface, prn=lambda x: self._process_packet(x))
        else:
            sniff(prn=lambda x: self._process_packet(x))  # list on all interfaces if none is specified

    def _process_packet(self, pkt: PacketData):
        data = PacketData(self._get_next_packet_id(), pkt)
        self.queue.put(data)

    def _get_next_packet_id(self) -> int:
        self.packet_id += 1
        return self.packet_id
