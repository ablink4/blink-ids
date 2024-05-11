"""
Top-level module for blink-ids.
"""
import threading

from packet_ingestor import PacketIngestor
from packet_queue import PacketQueue


def run(queue: PacketQueue):
    ingestor = PacketIngestor.PacketIngestor(queue)
    ingestor.start()


def consume(queue: PacketQueue):
    """
    Consumes packets from the queue.  This is just for testing purposes and will be replaced by the rules engine.
    """""
    while True:
        packet = queue.get()
        print(packet)


if __name__ == "__main__":
    packet_queue = PacketQueue.PacketQueue()

    producer = threading.Thread(target=run, args=(packet_queue,))
    consumer = threading.Thread(target=consume, args=(packet_queue, ))

    producer.start()
    consumer.start()

    producer.join()
    consumer.join()
