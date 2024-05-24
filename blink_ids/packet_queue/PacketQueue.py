"""
Implements a producer-consumer queue for PacketData objects so that they can be passed from
the packet ingestor to the rules engine.
"""
from queue import LifoQueue, Full, Empty
from typing import Optional

from blink_ids.packet_data.PacketData import PacketData


class PacketQueue:
    """
    A producer-consumer queue for PacketData objects.
    """

    def __init__(self):
        self.queue = LifoQueue()

    def put(self, packet_data: PacketData):
        """
        Put a PacketData object into the queue.
        :param packet_data: a packet to add to the queue
        """
        try:
            self.queue.put_nowait(packet_data)
        except Full:
            pass  # if the queue is full, packets will be dropped

    def get(self) -> Optional[PacketData]:
        """
        Get a PacketData object from the queue.
        :return: The last-added packet in the queue or None if the queue is empty.
        """
        try:
            return self.queue.get(timeout=5)  # if you block forever you can't interrupt the process
        except Empty:
            return None
