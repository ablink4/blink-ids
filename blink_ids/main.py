"""
Top-level module for blink-ids.
"""

import threading
import argparse

from blink_ids.logging_config.logging_config import logger
from blink_ids.packet_ingestor import PacketIngestor
from blink_ids.packet_queue import PacketQueue
from blink_ids.rule_parser import rule_parser


def run(queue: PacketQueue):
    ingestor = PacketIngestor.PacketIngestor(queue)
    ingestor.start()


def consume(queue: PacketQueue):
    """
    Consumes packets from the queue.  This is just for testing purposes and will be replaced by the rules engine.
    """""
    while True:
        packet = queue.get()
        logger.info(packet)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Blink-ids")
    parser.add_argument("--rules", help="Path to rules file directory", required=True)
    args = parser.parse_args()

    rule_parser.parse_rules_from_directory(args.rules)

    packet_queue = PacketQueue.PacketQueue()

    producer = threading.Thread(target=run, args=(packet_queue,))
    consumer = threading.Thread(target=consume, args=(packet_queue, ))

    producer.start()
    consumer.start()

    producer.join()
    consumer.join()
