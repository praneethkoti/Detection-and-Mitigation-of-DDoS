"""Benign background traffic generator.

Companion to udp_flood.py and random_dst_flood.py:

- benign_traffic.py        many sources, many destinations  -> high entropy (baseline)
- udp_flood.py             one source, one destination      -> dst-IP entropy collapses
- random_dst_flood.py      one source, many destinations    -> dst-IP entropy stays high

Generates bounded-count UDP traffic with randomized public-ish source IPs
and randomized destinations across 10.0.0.[s..e]. Used to establish the
no-attack entropy baseline against which the detector's threshold is set.
"""

from __future__ import annotations

import argparse
import logging
import sys
from random import randint

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, UDP, Ether, sendp  # noqa: E402

from ddos_sdn.utils.network import resolve_interface  # noqa: E402

EXCLUDED_FIRST_OCTETS = {10, 127, 254, 1, 2, 169, 172, 192}
DEFAULT_RANGE_START = 2
DEFAULT_RANGE_END = 64
DEFAULT_COUNT = 1000
DEFAULT_INTER = 0.1
DEFAULT_DPORT = 80
DEFAULT_SPORT = 2


def generate_source_ip() -> str:
    """Random IPv4 whose first octet is not in EXCLUDED_FIRST_OCTETS.

    Excludes RFC-1918, loopback, link-local, and the destination /8 (10.0.0.0/8)
    so source != destination by construction.
    """
    first = randint(1, 255)
    while first in EXCLUDED_FIRST_OCTETS:
        first = randint(1, 255)
    return f"{first}.{randint(1, 255)}.{randint(1, 255)}.{randint(1, 255)}"


def random_destination_ip(lower: int, upper: int) -> str:
    return f"10.0.0.{randint(lower, upper)}"


def generate(
    range_start: int,
    range_end: int,
    count: int,
    inter: float,
    interface: str | None,
) -> int:
    iface = resolve_interface(interface)
    sent = 0
    for _ in range(count):
        src = generate_source_ip()
        dst = random_destination_ip(range_start, range_end)
        pkt = Ether() / IP(src=src, dst=dst) / UDP(sport=DEFAULT_SPORT, dport=DEFAULT_DPORT)
        if iface is not None:
            sendp(pkt, iface=iface, inter=inter, verbose=0)
        else:
            sendp(pkt, inter=inter, verbose=0)
        sent += 1
    return sent


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benign background UDP traffic generator. "
        "Random source IPs (excluding RFC-1918/loopback/link-local), "
        "random destinations in 10.0.0.[start..end].",
    )
    parser.add_argument(
        "-s",
        "--start",
        type=int,
        default=DEFAULT_RANGE_START,
        help=f"low end of destination range 10.0.0.X (default: {DEFAULT_RANGE_START})",
    )
    parser.add_argument(
        "-e",
        "--end",
        type=int,
        default=DEFAULT_RANGE_END,
        help=f"high end of destination range 10.0.0.X (default: {DEFAULT_RANGE_END})",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=DEFAULT_COUNT,
        help=f"number of packets to send (default: {DEFAULT_COUNT})",
    )
    parser.add_argument(
        "--inter",
        type=float,
        default=DEFAULT_INTER,
        help=f"inter-packet delay in seconds (default: {DEFAULT_INTER})",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="network interface to send packets on (default: auto-select via psutil)",
    )
    args = parser.parse_args(argv)
    if args.start < 0 or args.end > 255 or args.start > args.end:
        parser.error("--start and --end must satisfy 0 <= start <= end <= 255")
    if args.count <= 0:
        parser.error("--count must be > 0")
    if args.inter < 0:
        parser.error("--inter must be >= 0")
    return args


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    sent = generate(
        range_start=args.start,
        range_end=args.end,
        count=args.count,
        inter=args.inter,
        interface=args.interface,
    )
    print(
        f"benign_traffic: sent {sent} packets to 10.0.0.[{args.start}..{args.end}] "
        f"with inter={args.inter}s"
    )


if __name__ == "__main__":
    main()
